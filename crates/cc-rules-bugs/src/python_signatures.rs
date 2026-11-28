//! Resolve Python argument names and filing methods from visible declarations.

use camino::{Utf8Path, Utf8PathBuf};
use cc_frontend::LanguageFrontend;
use cc_frontend_python::syntax::{children, text, Imports};
use cc_frontend_python::PythonFrontend;
use cc_rules::RuleContext;
use tree_sitter::Node;

use crate::python_calls::{self, ancestors, field, is_scope, name, parameter_name};

pub(crate) struct Syntax<'a> {
    pub(crate) path: &'a Utf8Path,
    pub(crate) source: &'a str,
    pub(crate) imports: &'a Imports<'a>,
    pub(crate) context: &'a RuleContext<'a>,
}

pub(crate) struct Definition<'a> {
    pub(crate) node: Node<'a>,
    pub(crate) source: &'a str,
    pub(crate) imports: &'a Imports<'a>,
    path: &'a Utf8Path,
}

impl Syntax<'_> {
    pub(crate) fn detail_argument(
        &self,
        arg: Node<'_>,
        is_detail: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let args = arg.parent().filter(|node| node.kind() == "argument_list")?;
        let callee = field(args.parent()?, "function")?;
        let argument = if arg.kind() == "keyword_argument" {
            Argument::Keyword(text(field(arg, "name")?, self.source))
        } else {
            Argument::Positional(argument_index(args, arg)?)
        };
        self.with_definition(callee, &|definition, bound| {
            definition.detail_parameter(argument, bound, &is_detail)
        })
    }

    pub(crate) fn with_definition<T>(
        &self,
        callee: Node<'_>,
        visit: &dyn Fn(Definition<'_>, bool) -> Option<T>,
    ) -> Option<T> {
        if self.imports.qualified_name(callee).is_some() || callee.kind() == "identifier" {
            return self.with_named_definition(callee, &|definition| visit(definition, false));
        }
        let member = name(callee, self.source)?;
        let receiver = field(callee, "object")?;
        self.with_receiver_class(receiver, 4, &|class| {
            let method = direct_definition(field(class.node, "body")?, member, class.source)?;
            visit(
                Definition {
                    node: method,
                    ..class
                },
                true,
            )
        })
    }

    fn with_receiver_class<T>(
        &self,
        receiver: Node<'_>,
        depth: usize,
        visit: &dyn Fn(Definition<'_>) -> Option<T>,
    ) -> Option<T> {
        let remaining = depth.checked_sub(1)?;
        match receiver.kind() {
            "identifier" if text(receiver, self.source) == "self" => {
                let class = ancestors(receiver).find(|node| node.kind() == "class_definition")?;
                visit(self.definition(class))
            }
            "call" => self.with_class(field(receiver, "function")?, visit),
            "identifier" => {
                if let Some(value) = python_calls::identifier_assignment(receiver, self.imports)
                    .and_then(|assignment| field(assignment, "right"))
                {
                    return self.with_receiver_class(value, remaining, visit);
                }
                self.with_class(parameter_type(receiver, self.source)?, visit)
            }
            "attribute" => {
                let member = name(receiver, self.source)?;
                self.with_receiver_class(field(receiver, "object")?, remaining, &|class| {
                    let syntax = Syntax {
                        path: class.path,
                        source: class.source,
                        imports: class.imports,
                        context: self.context,
                    };
                    match attribute_origin(class.node, member, class.source)? {
                        AttributeOrigin::Value(value) => {
                            syntax.with_receiver_class(value, remaining, visit)
                        }
                        AttributeOrigin::Annotation(annotation) => {
                            syntax.with_class(annotation, visit)
                        }
                    }
                })
            }
            _ => None,
        }
    }

    fn with_class<T>(
        &self,
        reference: Node<'_>,
        visit: &dyn Fn(Definition<'_>) -> Option<T>,
    ) -> Option<T> {
        self.with_named_definition(reference, &|definition| {
            (definition.node.kind() == "class_definition").then_some(())?;
            visit(definition)
        })
    }

    fn with_named_definition<T>(
        &self,
        reference: Node<'_>,
        visit: &dyn Fn(Definition<'_>) -> Option<T>,
    ) -> Option<T> {
        if let Some(target) = self.imports.qualified_name(reference) {
            let (module, symbol) = target.rsplit_once('.')?;
            let module = if module.is_empty() && target.starts_with('.') {
                "."
            } else {
                module
            };
            let paths = module_paths(self.path, module)?;
            let path = self.import_path(&paths)?;
            let source = std::str::from_utf8(self.context.source.get(&path)).ok()?;
            let tree = PythonFrontend::new().parse(source).ok()?;
            let root = tree.root_node();
            let decl = direct_definition(root, symbol, source)?;
            let imports = Imports::new(root, source);
            return visit(Definition {
                node: decl,
                source,
                imports: &imports,
                path: &path,
            });
        }
        let decl = visible_definition(reference, name(reference, self.source)?, self.source)?;
        visit(self.definition(decl))
    }

    fn definition<'a>(&'a self, node: Node<'a>) -> Definition<'a> {
        Definition {
            node,
            source: self.source,
            imports: self.imports,
            path: self.path,
        }
    }

    fn import_path(&self, paths: &[Utf8PathBuf]) -> Option<Utf8PathBuf> {
        self.context
            .source
            .paths()
            .into_iter()
            .find(|path| paths.contains(path))
    }
}

#[derive(Clone, Copy)]
enum Argument<'a> {
    Positional(usize),
    Keyword(&'a str),
}

impl Definition<'_> {
    fn detail_parameter(
        &self,
        argument: Argument<'_>,
        bound: bool,
        is_detail: impl Fn(&str) -> bool,
    ) -> Option<String> {
        if self.node.kind() == "class_definition" {
            let body = field(self.node, "body")?;
            if let Some(init) = direct_definition(body, "__init__", self.source) {
                return detail_parameter(init, argument, true, self.source, is_detail);
            }
            if self.is_dataclass() {
                return dataclass_argument(body, argument, self.source)
                    .filter(|name| is_detail(name));
            }
            return None;
        }
        detail_parameter(self.node, argument, bound, self.source, is_detail)
    }

    fn is_dataclass(&self) -> bool {
        self.node.parent().is_some_and(|parent| {
            parent.kind() == "decorated_definition"
                && children(parent)
                    .filter(|node| node.kind() == "decorator")
                    .filter_map(|node| children(node).find(|child| child.kind() != "comment"))
                    .filter_map(|node| {
                        if node.kind() == "call" {
                            field(node, "function")
                        } else {
                            Some(node)
                        }
                    })
                    .any(|decorator| {
                        self.imports.qualified_name(decorator).as_deref()
                            == Some("dataclasses.dataclass")
                    })
        })
    }
}

fn module_paths(path: &Utf8Path, module: &str) -> Option<Vec<Utf8PathBuf>> {
    let tail = module.trim_start_matches('.');
    let dots = module.len() - tail.len();
    let mut prefix = if dots > 0 {
        let mut directory = path.parent()?;
        for _ in 1..dots {
            directory = directory.parent()?;
        }
        directory.to_owned()
    } else if path.starts_with("src") {
        Utf8PathBuf::from("src")
    } else {
        Utf8PathBuf::new()
    };
    prefix.extend(tail.split('.').filter(|part| !part.is_empty()));
    let mut candidates = vec![prefix.join("__init__.py")];
    if !tail.is_empty() {
        candidates.push(prefix.with_extension("py"));
    }
    Some(candidates)
}

fn argument_index(args: Node<'_>, arg: Node<'_>) -> Option<usize> {
    if matches!(arg.kind(), "list_splat" | "dictionary_splat" | "comment") {
        return None;
    }
    let mut position = 0;
    for prior in children(args).take_while(|node| *node != arg) {
        match prior.kind() {
            "list_splat" | "dictionary_splat" | "keyword_argument" => return None,
            "comment" => {}
            _ => position += 1,
        }
    }
    Some(position)
}

pub(crate) fn visible_definition<'tree>(
    node: Node<'tree>,
    spelling: &str,
    source: &str,
) -> Option<Node<'tree>> {
    ancestors(node)
        .filter(|owner| is_scope(*owner) || owner.kind() == "module")
        .filter(|owner| owner.kind() != "class_definition")
        .filter_map(|owner| {
            if owner.kind() == "module" {
                Some(owner)
            } else {
                field(owner, "body")
            }
        })
        .find_map(|body| direct_definition(body, spelling, source))
}

pub(crate) fn direct_definition<'tree>(
    body: Node<'tree>,
    spelling: &str,
    source: &str,
) -> Option<Node<'tree>> {
    children(body)
        .filter_map(|member| match member.kind() {
            "function_definition" | "class_definition" => Some(member),
            "decorated_definition" => field(member, "definition"),
            _ => None,
        })
        .filter(|member| field(*member, "name").is_some_and(|node| text(node, source) == spelling))
        .last()
}

fn dataclass_argument(body: Node<'_>, argument: Argument<'_>, source: &str) -> Option<String> {
    let mut fields = assignments(body)
        .filter(|assign| field(*assign, "type").is_some())
        .filter_map(|assign| field(assign, "left"))
        .filter(|node| node.kind() == "identifier");
    let parameter = match argument {
        Argument::Positional(index) => fields.nth(index)?,
        Argument::Keyword(keyword) => fields.find(|node| text(*node, source) == keyword)?,
    };
    Some(text(parameter, source).to_owned())
}

fn detail_parameter(
    function: Node<'_>,
    argument: Argument<'_>,
    bound: bool,
    source: &str,
    is_detail: impl Fn(&str) -> bool,
) -> Option<String> {
    let params = field(function, "parameters")?;
    let parameter = match argument {
        Argument::Positional(index) => children(params)
            .take_while(|param| !keyword_only(*param))
            .filter_map(parameter_name)
            .nth(index + usize::from(bound))?,
        Argument::Keyword(keyword) => children(params)
            .filter_map(parameter_name)
            .find(|param| text(*param, source) == keyword)?,
    };
    let spelling = text(parameter, source);
    is_detail(spelling).then(|| spelling.to_owned())
}

fn keyword_only(param: Node<'_>) -> bool {
    matches!(
        param.kind(),
        "keyword_separator" | "list_splat_pattern" | "dictionary_splat_pattern"
    ) || (param.kind() == "typed_parameter"
        && children(param).any(|part| {
            matches!(
                part.kind(),
                "list_splat_pattern" | "dictionary_splat_pattern"
            )
        }))
}

fn parameter_type<'tree>(reference: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let owner = ancestors(reference).find(|node| is_scope(*node))?;
    let params = field(owner, "parameters")?;
    let param = children(params).find(|param| {
        parameter_name(*param).is_some_and(|ident| text(ident, source) == text(reference, source))
    })?;
    annotation_name(param)
}

fn annotation_name(node: Node<'_>) -> Option<Node<'_>> {
    let annotation = field(node, "type")?;
    if annotation.kind() == "type" {
        return children(annotation).find(|child| child.kind() != "comment");
    }
    Some(annotation)
}

enum AttributeOrigin<'tree> {
    Value(Node<'tree>),
    Annotation(Node<'tree>),
}

fn attribute_origin<'tree>(
    class: Node<'tree>,
    member: &str,
    source: &str,
) -> Option<AttributeOrigin<'tree>> {
    let body = field(class, "body")?;
    if let Some(init_body) =
        direct_definition(body, "__init__", source).and_then(|init| field(init, "body"))
    {
        if let Some(value) = assignments(init_body)
            .filter_map(|assignment| assigned_attribute(assignment, member, source))
            .last()
        {
            return Some(AttributeOrigin::Value(value));
        }
    }
    let declaration = assignments(body).find(|assignment| {
        field(*assignment, "left").is_some_and(|node| text(node, source) == member)
    })?;
    annotation_name(declaration).map(AttributeOrigin::Annotation)
}

pub(crate) fn assignments(body: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    children(body)
        .filter(|node| node.kind() == "expression_statement")
        .filter_map(|node| children(node).find(|child| child.kind() == "assignment"))
}

fn assigned_attribute<'tree>(
    assignment: Node<'tree>,
    member: &str,
    source: &str,
) -> Option<Node<'tree>> {
    python_calls::assignment_value(assignment, |node| {
        name(node, source) == Some(member)
            && field(node, "object").is_some_and(|object| text(object, source) == "self")
    })
}

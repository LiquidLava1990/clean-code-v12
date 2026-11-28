//! Concrete Python syntax helpers for rules that need import bindings.

use std::collections::HashMap;
use tree_sitter::Node;

/// Direct named children, excluding comments.
pub fn children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    (0..node.named_child_count())
        .filter_map(move |index| node.named_child(index))
        .filter(|child| child.kind() != "comment")
}

/// Syntax nodes in source order, including the root.
pub fn preorder(root: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut cursor = root.walk();
    let mut next = Some(root);
    std::iter::from_fn(move || {
        let node = next?;
        if cursor.goto_first_child() {
            next = Some(cursor.node());
        } else {
            loop {
                if cursor.node() == root {
                    next = None;
                    break;
                }
                if cursor.goto_next_sibling() {
                    next = Some(cursor.node());
                    break;
                }
                cursor.goto_parent();
            }
        }
        Some(node)
    })
}

/// Source text covered by a syntax node.
pub fn text<'s>(node: Node<'_>, source: &'s str) -> &'s str {
    &source[node.byte_range()]
}

/// An import target and the module that exported it.
#[derive(Clone, Debug)]
pub struct ImportBinding {
    /// Fully spelled path, retaining leading dots on relative imports.
    pub target: String,
    /// Module of a from-import, or the imported module for a plain import.
    pub module: String,
}

type Binding = (usize, Option<ImportBinding>);

/// Lexical name bindings for a single Python file.
pub struct Imports<'s> {
    source: &'s str,
    scopes: HashMap<(usize, &'s str), Vec<Binding>>,
}

impl<'s> Imports<'s> {
    /// Index imports and local names that can shadow them.
    pub fn new(root: Node<'_>, source: &'s str) -> Self {
        let mut imports = Self {
            source,
            scopes: HashMap::new(),
        };
        for node in preorder(root) {
            match node.kind() {
                "import_statement" | "import_from_statement" => imports.add_import(node),
                "assignment"
                | "augmented_assignment"
                | "for_statement"
                | "for_in_clause"
                | "named_expression" => {
                    let target = node
                        .child_by_field_name("left")
                        .or_else(|| node.child_by_field_name("name"));
                    if let Some(target) = target {
                        imports.shadow_pattern(scope(node), target, node.end_byte());
                    }
                }
                "as_pattern" => {
                    if let Some(alias) = node.child_by_field_name("alias") {
                        imports.shadow_pattern(scope(node), alias, alias.end_byte());
                    }
                }
                "function_definition" | "class_definition" | "lambda" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        imports.shadow_pattern(scope(node), name, name.end_byte());
                    }
                    if let Some(params) = node.child_by_field_name("parameters") {
                        for param in children(params) {
                            imports.shadow_pattern(Some(node), param, node.start_byte());
                        }
                    }
                }
                _ => {}
            }
        }
        imports
    }

    /// Resolve the import visible to an identifier at its use site.
    pub fn resolve(&self, name: Node<'_>) -> Option<&ImportBinding> {
        let (_, import) = self.binding(name).flatten()?;
        import.as_ref()
    }

    /// End offset of the visible non-import binding, when it precedes the use.
    pub fn local_binding_end(&self, name: Node<'_>) -> Option<usize> {
        let (offset, import) = self.binding(name).flatten()?;
        import.is_none().then_some(*offset)
    }

    /// Whether a lexical binding hides a builtin of the same name.
    pub fn has_binding(&self, name: Node<'_>) -> bool {
        self.binding(name).is_some()
    }

    /// Resolve an identifier or attribute chain rooted at an import.
    pub fn qualified_name(&self, node: Node<'_>) -> Option<String> {
        match node.kind() {
            "identifier" => Some(self.resolve(node)?.target.clone()),
            "attribute" => {
                let object = self.qualified_name(node.child_by_field_name("object")?)?;
                let member = text(node.child_by_field_name("attribute")?, self.source);
                Some(format!("{object}.{member}"))
            }
            _ => None,
        }
    }

    fn binding(&self, name: Node<'_>) -> Option<Option<&Binding>> {
        let spelling = text(name, self.source);
        let mut current = scope(name);
        let mut in_function = false;
        while let Some(owner) = current {
            current = scope(owner);
            if in_function && owner.kind() == "class_definition" {
                continue;
            }
            let function_scope = is_function_scope(owner);
            in_function |= function_scope;
            let Some(bindings) = self.scopes.get(&(owner.id(), spelling)) else {
                continue;
            };
            let visible = bindings
                .iter()
                .filter(|(offset, _)| *offset <= name.start_byte())
                .max_by_key(|(offset, _)| *offset);
            if visible.is_some() || function_scope {
                return Some(visible);
            }
        }
        None
    }

    fn add_import(&mut self, node: Node<'_>) {
        let from = node
            .child_by_field_name("module_name")
            .map(|module| dotted_name(module, self.source));
        let mut cursor = node.walk();
        for entry in node.children_by_field_name("name", &mut cursor) {
            let imported = entry.child_by_field_name("name").unwrap_or(entry);
            let alias = entry.child_by_field_name("alias");
            let Some(bound) = alias.or_else(|| children(imported).next()) else {
                continue;
            };
            let name = dotted_name(imported, self.source);
            let (module, target) = match &from {
                Some(module) => {
                    let separator = if module.ends_with('.') { "" } else { "." };
                    (module.clone(), format!("{module}{separator}{name}"))
                }
                None => {
                    let target =
                        alias.map_or_else(|| text(bound, self.source).to_owned(), |_| name.clone());
                    (name, target)
                }
            };
            self.bind(
                scope(node),
                bound,
                node.end_byte(),
                Some(ImportBinding { target, module }),
            );
        }
    }

    fn shadow_pattern(&mut self, owner: Option<Node<'_>>, target: Node<'_>, offset: usize) {
        match target.kind() {
            "identifier" => self.bind(owner, target, offset, None),
            "default_parameter" | "typed_default_parameter" => {
                if let Some(name) = target.child_by_field_name("name") {
                    self.shadow_pattern(owner, name, offset);
                }
            }
            "typed_parameter" => {
                if let Some(name) = children(target).next() {
                    self.shadow_pattern(owner, name, offset);
                }
            }
            "as_pattern_target"
            | "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
            | "tuple"
            | "list"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => {
                for child in children(target) {
                    self.shadow_pattern(owner, child, offset);
                }
            }
            _ => {}
        }
    }

    fn bind(
        &mut self,
        owner: Option<Node<'_>>,
        name: Node<'_>,
        offset: usize,
        binding: Option<ImportBinding>,
    ) {
        if let Some(owner) = owner {
            self.scopes
                .entry((owner.id(), text(name, self.source)))
                .or_default()
                .push((offset, binding));
        }
    }
}

fn dotted_name(node: Node<'_>, source: &str) -> String {
    preorder(node)
        .filter(|part| matches!(part.kind(), "." | "identifier"))
        .map(|part| text(part, source))
        .collect()
}

fn scope(node: Node<'_>) -> Option<Node<'_>> {
    let mut child = node;
    while let Some(parent) = child.parent() {
        match parent.kind() {
            "module" => return Some(parent),
            "class_definition" | "function_definition" | "lambda"
                if parent.child_by_field_name("body") == Some(child) =>
            {
                return Some(parent)
            }
            _ if is_function_scope(parent)
                && !matches!(parent.kind(), "function_definition" | "lambda") =>
            {
                return Some(parent);
            }
            _ => child = parent,
        }
    }
    None
}

fn is_function_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition"
            | "lambda"
            | "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression"
    )
}

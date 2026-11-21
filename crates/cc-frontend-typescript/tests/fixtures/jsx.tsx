import * as React from "react";

export function HelloPanel(props: { name: string }): JSX.Element {
    return <div className="hi">Hello {props.name}</div>;
}

export const Goodbye = (): JSX.Element => <span>bye</span>;

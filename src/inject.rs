use anyhow::Context;
use html5ever::interface::{AppendNode, TreeSink};
use html5ever::namespace_url;
use html5ever::tendril::TendrilSink;
use html5ever::{local_name, ns, parse_document, serialize, Attribute, QualName};
use markup5ever_rcdom::{Handle, Node, NodeData, RcDom, SerializableHandle};
use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};
use sha3::Digest;
use sha3::digest::Update;

pub fn inject_ekto(content_root: PathBuf, ekto_lib: &str, ekto_lib_hash: String) -> anyhow::Result<()> {
    let index = content_root.join("index.html");
    if !index.exists() {
        anyhow::bail!("No index.html found in content root");
    }

    let doc = parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut std::fs::File::open(&index)?)
        .context("Failed to parse index.html")?;

    inject_ekto_shim_script(&doc)?;

    require_ekto_lib_latest(content_root, ekto_lib, ekto_lib_hash)?;

    let document: SerializableHandle = doc.document.clone().into();
    let mut file = std::fs::File::create(&index)?;
    serialize(&mut file, &document, Default::default()).context("serialization failed")?;

    Ok(())
}

pub fn require_ekto_lib_latest(content_root: PathBuf, ekto_lib: &str, ekto_lib_hash: String) -> anyhow::Result<String> {
    let ekto_lib_name = format!("ekto-lib-{ekto_lib_hash}.js");
    let buf = content_root.join(ekto_lib_name.clone());
    if !buf.exists() {
        // TODO could remove older bundles here
        let mut lib_file = std::fs::File::create_new(buf)?;
        lib_file.write_all(ekto_lib.as_bytes())?;
    }

    Ok(ekto_lib_name)
}

fn inject_ekto_shim_script(doc: &RcDom) -> anyhow::Result<()> {
    if let Some(html) = first_child(&doc.document, "html") {
        if let Some(head) = first_child(&html, "head") {
            let shim_node = AppendNode(Node::new(NodeData::Element {
                name: QualName::new(None, ns!(html), local_name!("script")),
                attrs: RefCell::new(vec![Attribute {
                    name: QualName::new(None, ns!(), local_name!("type")),
                    value: "module".into(),
                }, Attribute {
                    name: QualName::new(None, ns!(), local_name!("src")),
                    value: "/ekto-shim.js".into(),
                }]),
                template_contents: RefCell::new(None),
                mathml_annotation_xml_integration_point: false,
            }));

            if let Some(script) = first_child(&head, "script") {
                // If there is another script tag in the head, insert before it so the shim is loaded first
                doc.append_before_sibling(&script, shim_node);
            } else {
                // Otherwise, just append to the end of the head
                doc.append(&head, shim_node);
            }
        }
    }

    Ok(())
}

fn first_child(handle: &Handle, name: &str) -> Option<Handle> {
    handle
        .children
        .borrow()
        .iter()
        .find(|child| match &child.data {
            NodeData::Element { name: n, .. } => n.local.as_bytes() == name.as_bytes(),
            _ => false,
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_edit(input: &str) -> String {
        let dom = parse_document(RcDom::default(), Default::default())
            .from_utf8()
            .read_from(&mut input.as_bytes())
            .unwrap();

        inject_ekto_shim_script(&dom).unwrap();

        let document: SerializableHandle = dom.document.clone().into();
        let mut output = Vec::new();
        serialize(&mut output, &document, Default::default()).unwrap();

        String::from_utf8(output).unwrap()
    }

    #[test]
    fn inject_ekto_shim_with_no_other_scripts() {
        let input = r#"
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Test</title>
                </head>
                <body>
                    <h1>Hello, world!</h1>
                </body>
            </html>
        "#;

        let expected = "<!DOCTYPE html><html><head>\n                    <title>Test</title>\n                <script src=\"/ekto-shim.js\"></script></head>\n                <body>\n                    <h1>Hello, world!</h1>\n                \n            \n        </body></html>";

        assert_eq!(expected, test_edit(input));
    }

    #[test]
    fn inject_ekto_shim_before_other_scripts() {
        let input = r#"
            <!DOCTYPE html>
            <html>
                <head>
                    <title>Test</title>
                    <script src="other-script.js"></script>
                </head>
                <body>
                    <h1>Hello, world!</h1>
                </body>
            </html>
        "#;

        let expected = "<!DOCTYPE html><html><head>\n                    <title>Test</title>\n                    <script src=\"/ekto-shim.js\"></script><script src=\"other-script.js\"></script>\n                </head>\n                <body>\n                    <h1>Hello, world!</h1>\n                \n            \n        </body></html>";

        assert_eq!(expected, test_edit(input));
    }
}

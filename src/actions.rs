#![allow(clippy::suspicious_else_formatting)]
#![allow(clippy::toplevel_ref_arg)]
// use crate::Error;
use casbin::{error::AdapterError, Error as CasbinError, Filter, Result};
use futures::stream::StreamExt;
use mongodb::{
    bson::{doc, Document, Regex},
    Client, Collection, Cursor, Database,
};

use crate::models::{CasbinRule, NewCasbinRule};

pub async fn new(db: &Database) -> Result<Document> {
    let create_command = doc! {
      "createIndexes": "casbin_rule",
      "indexes": [{
          "key": {
              "ptype": 1,
              "v0": 1,
              "v1": 1,
              "v2": 1,
              "v3": 1,
              "v4": 1,
              "v5": 1,
          },
          "name": "unique_key_mongo_adapter",
          "unique": true
      }]
    };

    db.run_command(create_command, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
}

fn filtered_where_values<'a>(filter: &Filter<'a>) -> ([&'a str; 6], [&'a str; 6]) {
    let mut g_filter: [&'a str; 6] = [".*", ".*", ".*", ".*", ".*", ".*"];
    let mut p_filter: [&'a str; 6] = [".*", ".*", ".*", ".*", ".*", ".*"];
    for (idx, val) in filter.g.iter().enumerate() {
        if val != &"" {
            g_filter[idx] = val;
        }
    }
    for (idx, val) in filter.p.iter().enumerate() {
        if val != &"" {
            p_filter[idx] = val;
        }
    }
    (g_filter, p_filter)
}

fn normalize_casbin_rule(mut rule: Vec<String>, field_index: usize) -> Vec<String> {
    rule.resize(6 - field_index, String::from(""));
    rule
}

async fn casbin_rules_from_cursor(cursor: Cursor) -> Vec<CasbinRule> {
    let rules_doc: Vec<mongodb::error::Result<Document>> = cursor.collect().await;

    let result: Vec<CasbinRule> = rules_doc
        .iter()
        .filter_map(|result| {
            if let Ok(document) = result {
                let doc_format = format!("{:?}", document);
                let rule = CasbinRule::from_document(document).unwrap();
                let rule_format = format!("{:?}", rule);
                Some(rule)
            } else {
                None
            }
        })
        .collect();

    let r_format = format!("{:?}", result);

    result
}

pub(crate) async fn load_policy(collection: &Collection) -> Result<Vec<CasbinRule>> {
    let rules_cursor = collection
        .find(None, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    let casbin_rules = casbin_rules_from_cursor(rules_cursor).await;

    Ok(casbin_rules)
}

pub(crate) async fn load_filtered_policy<'a>(
    collection: &Collection,
    filter: &Filter<'_>,
) -> Result<Vec<CasbinRule>> {
    let (g_filter, p_filter) = filtered_where_values(filter);

    let mut query = Document::new();

    let g_filter = {
        let mut g_doc = Document::new();

        g_doc.insert(
            "ptype",
            Regex {
                pattern: String::from("^g"),
                options: String::from("i"),
            },
        );
        g_doc.insert(
            "v0",
            Regex {
                pattern: String::from(g_filter[0]),
                options: String::from("i"),
            },
        );
        g_doc.insert(
            "v1",
            Regex {
                pattern: String::from(g_filter[1]),
                options: String::from("i"),
            },
        );
        g_doc.insert(
            "v2",
            Regex {
                pattern: String::from(g_filter[2]),
                options: String::from("i"),
            },
        );
        g_doc.insert(
            "v3",
            Regex {
                pattern: String::from(g_filter[3]),
                options: String::from("i"),
            },
        );
        g_doc.insert(
            "v4",
            Regex {
                pattern: String::from(g_filter[4]),
                options: String::from("i"),
            },
        );
        g_doc.insert(
            "v5",
            Regex {
                pattern: String::from(g_filter[5]),
                options: String::from("i"),
            },
        );

        g_doc
    };

    let p_filter = {
        let mut p_doc = Document::new();

        p_doc.insert(
            "ptype",
            Regex {
                pattern: String::from("^p"),
                options: String::from("i"),
            },
        );
        p_doc.insert(
            "v0",
            Regex {
                pattern: String::from(p_filter[0]),
                options: String::from("i"),
            },
        );
        p_doc.insert(
            "v1",
            Regex {
                pattern: String::from(p_filter[1]),
                options: String::from("i"),
            },
        );
        p_doc.insert(
            "v2",
            Regex {
                pattern: String::from(p_filter[2]),
                options: String::from("i"),
            },
        );
        p_doc.insert(
            "v3",
            Regex {
                pattern: String::from(p_filter[3]),
                options: String::from("i"),
            },
        );
        p_doc.insert(
            "v4",
            Regex {
                pattern: String::from(p_filter[4]),
                options: String::from("i"),
            },
        );
        p_doc.insert(
            "v5",
            Regex {
                pattern: String::from(p_filter[5]),
                options: String::from("i"),
            },
        );

        p_doc
    };

    let query = doc! {
        "$or": [
            g_filter,
            p_filter,
        ]
    };

    let formatted_query = format!("{:?}", query);

    let rules_cursor = collection
        .find(Some(query), None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    let casbin_rules = casbin_rules_from_cursor(rules_cursor).await;

    let _formatted_rules = format!("{:?}", casbin_rules);

    Ok(casbin_rules)
}

pub(crate) async fn save_policy<'a>(
    collection: &Collection,
    rules: Vec<NewCasbinRule<'a>>,
) -> Result<()> {
    collection
        .delete_many(doc! {}, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    let docs: Vec<Document> = rules.iter().map(|rule| rule.into_document()).collect();

    collection
        .insert_many(docs, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(())
}

pub(crate) async fn add_policy(collection: &Collection, rule: NewCasbinRule<'_>) -> Result<bool> {
    let rule_doc = rule.into_document();

    collection
        .insert_one(rule_doc, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(true)
}

pub(crate) async fn add_policies(
    collection: &Collection,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<bool> {
    let docs: Vec<Document> = rules.iter().map(|rule| rule.into_document()).collect();

    collection
        .insert_many(docs, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(true)
}

pub async fn remove_policy(collection: &Collection, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule, 0);

    collection
        .find_one_and_delete(
            doc! {
                "ptype": pt,
                "v0": &rule[0],
                "v1": &rule[1],
                "v2": &rule[2],
                "v3": &rule[3],
                "v4": &rule[4],
                "v5": &rule[5],
            },
            None,
        )
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(true)
}

pub async fn remove_policies(
    collection: &Collection,
    pt: &str,
    rules: Vec<Vec<String>>,
) -> Result<bool> {
    // Fuck this
    for rule in rules {
        remove_policy(collection, pt, rule)
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    }

    Ok(true)
}

pub async fn remove_filtered_policy(
    collection: &Collection,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule(field_values, field_index);
    let mut filter = Document::new();

    // These are always present
    filter.insert("ptype", pt);
    // filter.insert(
    //     "v5",
    //     doc! {
    //         "$or": [
    //             {
    //                 "v5": "null"
    //             },
    //             {
    //                 "v5": field_values[5],
    //             }
    //         ]
    //     },
    // );

    // Migrated from go
    if field_index <= 0 && 0 < field_index + field_values.len() {
        if field_values[0 - field_index] != "" {
            filter.insert("v0", (field_values[0 - field_index]).clone());
        }
    }
    if field_index <= 1 && 1 < field_index + field_values.len() {
        if field_values[1 - field_index] != "" {
            filter.insert("v1", (field_values[1 - field_index]).clone());
        }
    }
    if field_index <= 2 && 2 < field_index + field_values.len() {
        if field_values[2 - field_index] != "" {
            filter.insert("v2", (field_values[2 - field_index]).clone());
        }
    }
    if field_index <= 3 && 3 < field_index + field_values.len() {
        if field_values[3 - field_index] != "" {
            filter.insert("v3", (field_values[3 - field_index]).clone());
        }
    }
    if field_index <= 4 && 4 < field_index + field_values.len() {
        if field_values[4 - field_index] != "" {
            filter.insert("v4", (field_values[4 - field_index]).clone());
        }
    }
    if field_index <= 5 && 5 < field_index + field_values.len() {
        if field_values[5 - field_index] != "" {
            filter.insert("v5", (field_values[5 - field_index]).clone());
        }
    }

    collection
        .delete_many(filter, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    Ok(true)
}

pub(crate) async fn clear_policy(collection: &Collection) -> Result<()> {
    collection
        .delete_many(doc! {}, None)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    Ok(())
}

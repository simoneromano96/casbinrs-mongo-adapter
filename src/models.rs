use mongodb::bson::{document::ValueAccessError, oid::ObjectId, Document};

#[derive(Debug, Clone)]
/// CasbinRule represents a rule in Casbin.
pub(crate) struct CasbinRule {
    pub id: ObjectId,
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}

impl CasbinRule {
    pub fn from_document(document: &Document) -> Result<Self, ValueAccessError> {
        let id = document.get_object_id("_id")?.clone();
        let ptype = document.get_str("ptype")?.to_owned();
        let v0 = document.get_str("v0")?.to_owned();
        let v1 = document.get_str("v1")?.to_owned();
        let v2 = document.get_str("v2")?.to_owned();
        let v3 = document.get_str("v3")?.to_owned();
        let v4 = document.get_str("v4")?.to_owned();
        let v5 = document.get_str("v5")?.to_owned();

        Ok(Self {
            id,
            ptype,
            v0,
            v1,
            v2,
            v3,
            v4,
            v5,
        })
    }
}

#[derive(Debug)]
pub(crate) struct NewCasbinRule<'a> {
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}

impl<'a> NewCasbinRule<'a> {
    pub fn into_document(&'a self) -> Document {
        let mut document = Document::new();

        document.insert("ptype", self.ptype);
        document.insert("v0", self.v0);
        document.insert("v1", self.v1);
        document.insert("v2", self.v2);
        document.insert("v3", self.v3);
        document.insert("v4", self.v4);
        document.insert("v5", self.v5);

        document
    }
}
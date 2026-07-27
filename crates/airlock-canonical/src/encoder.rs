#[derive(Debug, Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_domain(domain: &[u8]) -> Self {
        let mut enc = Self::new();
        enc.buf.extend_from_slice(domain);
        enc
    }

    pub fn u64(&mut self, n: u64) -> &mut Self {
        self.buf.extend_from_slice(&n.to_le_bytes());
        self
    }

    pub fn u32(&mut self, n: u32) -> &mut Self {
        self.buf.extend_from_slice(&n.to_le_bytes());
        self
    }

    pub fn tag(&mut self, t: u8) -> &mut Self {
        self.buf.push(t);
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u64(b.len() as u64);
        self.buf.extend_from_slice(b);
        self
    }

    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    pub fn opt_str(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            None => self.tag(0),
            Some(v) => {
                self.tag(1);
                self.str(v)
            }
        }
    }

    pub fn opt_u64(&mut self, n: Option<u64>) -> &mut Self {
        match n {
            None => self.tag(0),
            Some(v) => {
                self.tag(1);
                self.u64(v)
            }
        }
    }

    pub fn bool(&mut self, b: bool) -> &mut Self {
        self.tag(u8::from(b))
    }

    pub fn list_str<S: AsRef<str>>(&mut self, xs: &[S]) -> &mut Self {
        self.u64(xs.len() as u64);
        for x in xs {
            self.str(x.as_ref());
        }
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_removes_concatenation_ambiguity() {
        let mut a = Encoder::new();
        a.str("ab").str("c");
        let mut b = Encoder::new();
        b.str("a").str("bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn empty_string_differs_from_absent() {
        let mut a = Encoder::new();
        a.opt_str(Some(""));
        let mut b = Encoder::new();
        b.opt_str(None);
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn empty_list_differs_from_single_empty_item() {
        let empty: [&str; 0] = [];
        let mut a = Encoder::new();
        a.list_str(&empty);
        let mut b = Encoder::new();
        b.list_str(&[""]);
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn argv_boundary_shift_changes_encoding() {
        let mut a = Encoder::new();
        a.list_str(&["rm", "-rf", "/"]);
        let mut b = Encoder::new();
        b.list_str(&["rm", "-rf /"]);
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn u64_is_little_endian() {
        let mut e = Encoder::new();
        e.u64(1);
        assert_eq!(e.finish(), vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }
}

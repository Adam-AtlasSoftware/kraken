// Reference translation of stripped_calc `evaluate` with its parser (corpus/src/stripped_calc.c):
// skip_ws, parse_number, parse_atom, parse_term, parse_expr.

struct Parser {
    p: *const u8,
    err: bool,
}

impl Parser {
    fn cur(&self) -> u8 {
        unsafe { *self.p }
    }

    fn advance(&mut self) {
        self.p = unsafe { self.p.add(1) };
    }

    fn skip_ws(&mut self) {
        // isspace in the C locale: space, \t, \n, \v, \f, \r
        while matches!(self.cur(), b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
            self.advance();
        }
    }

    fn parse_number(&mut self) -> i64 {
        let mut v: i64 = 0;
        let mut any = false;
        self.skip_ws();
        while self.cur().is_ascii_digit() {
            v = v.wrapping_mul(10).wrapping_add(i64::from(self.cur() - b'0'));
            self.advance();
            any = true;
        }
        if !any {
            self.err = true;
        }
        v
    }

    fn parse_atom(&mut self) -> i64 {
        self.skip_ws();
        if self.cur() == b'(' {
            self.advance();
            let v = self.parse_expr();
            self.skip_ws();
            if self.cur() != b')' {
                self.err = true;
            } else {
                self.advance();
            }
            return v;
        }
        if self.cur() == b'-' {
            self.advance();
            return self.parse_atom().wrapping_neg();
        }
        self.parse_number()
    }

    fn parse_term(&mut self) -> i64 {
        let mut v = self.parse_atom();
        loop {
            self.skip_ws();
            let op = self.cur();
            if op != b'*' && op != b'/' && op != b'%' {
                return v;
            }
            self.advance();
            let r = self.parse_atom();
            if op == b'*' {
                v = v.wrapping_mul(r);
            } else if r == 0 {
                self.err = true;
            } else {
                // i64::MIN / -1 traps in the original (idiv); here it panics, which the
                // differential test reports as the same kind of fault.
                v = if op == b'/' { v / r } else { v % r };
            }
        }
    }

    fn parse_expr(&mut self) -> i64 {
        let mut v = self.parse_term();
        loop {
            self.skip_ws();
            let op = self.cur();
            if op != b'+' && op != b'-' {
                return v;
            }
            self.advance();
            let r = self.parse_term();
            v = if op == b'+' { v.wrapping_add(r) } else { v.wrapping_sub(r) };
        }
    }
}

/// Evaluates the expression in the NUL-terminated `text`; stores the value in `*out` and returns
/// 0, or returns -1 (leaving `*out` alone) on a syntax error or division by zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn evaluate(text: *const u8, out: *mut i64) -> i32 {
    let mut ps = Parser { p: text, err: false };
    let v = ps.parse_expr();
    ps.skip_ws();
    if ps.err || ps.cur() != 0 {
        return -1;
    }
    unsafe { *out = v };
    0
}

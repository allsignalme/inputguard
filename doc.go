// Package inputguard inspects untrusted input (JSON documents, Go values, single strings) for content that
// becomes dangerous where it ends up: script in a page (XSS), template and JavaScript injection, SQL / NoSQL /
// shell / path injection, line breaks in headers, Unicode abuse (control, bidi, invisible characters, invalid
// UTF-8, look-alike scripts), malicious JSON structure (prototype pollution, duplicate keys, operator keys,
// documents built to be expensive), spreadsheet formulas, server-side requests to internal addresses and open
// redirects.
//
// A Guard is built once from options and is safe for concurrent use. It either cleans (ModeClean: the malicious
// part of a value is removed, the rest of the document is kept byte for byte) or rejects (ModeReject: nothing is
// changed and the report says which rules matched where). Reports carry rule ids and field paths, never values.
//
// How a value is treated depends on its context (text, URL, redirect target, identifier, secret, file path, header),
// chosen from the field name by a key table, from path patterns, or by a custom classifier. Rules come in two
// profiles (balanced, the default for cleaning; strict, the default for rejecting), and each rule or severity can
// be given its own action.
//
// Speed comes from doing nothing for clean input: a single pass over the bytes of a body, driven by a table built
// from the enabled rules, proves that most bodies cannot contain anything and returns them untouched without
// parsing or allocating. Otherwise one streaming pass over the document decodes only suspicious strings and
// splices the cleaned ones back in place.
//
// The net/http middleware is in the httpguard subpackage.
package inputguard

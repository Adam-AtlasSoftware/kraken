// KRAKEN native engine shim over the Ghidra decompiler library (libdecomp + Sleigh).
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Our own glue code: an Architecture whose LoadImage reads through a Rust callback, a global
// scope fed with function symbols from Rust, and a token-recording emitter for PrintC. Ghidra's
// headers stay out of this file so the cxx bridge only sees plain types.
#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

namespace kraken {

struct ImageSource;
struct InsnOut;
struct PcodeOpOut;
struct DecompOut;
struct JumpEdgeOut;
struct CommentIn;
struct ContextOut;

// Registers the decompiler capabilities and scans `sleigh_home` (a Ghidra install root) for
// language definitions. Idempotent; must run before `new_session`.
void start_library(rust::Str sleigh_home);

// Whether the library knows the language id (such as "x86:LE:64:default").
bool has_language(rust::Str language_id);

class Session {
public:
  struct Impl;
  explicit Session(std::unique_ptr<Impl> impl);
  ~Session();
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;

  // Adds (or renames) a function symbol in the global scope.
  void add_function(uint64_t addr, rust::Str name);
  // Creates the function at `addr` with its default name when there is none (as a decompile or
  // a switch analysis of an unknown address does).
  void ensure_function(uint64_t addr);
  // Decodes up to `max` instructions starting at `addr`, stopping early at undecodable bytes.
  rust::Vec<InsnOut> decode(uint64_t addr, uint32_t max);
  // Raw p-code of the instructions in [start, end).
  rust::Vec<PcodeOpOut> lift(uint64_t start, uint64_t end);
  // Decompiles the function at `addr` (created with a default name when unknown). With a
  // non-zero `timeout_ms` the decompile gives up at the first action break point after the
  // deadline; it also gives up when the image source reports an interrupt. Either sets the
  // matching flag in the result and leaves the text empty.
  DecompOut decompile(uint64_t addr, uint32_t timeout_ms);
  // Follows the flow of the function at `addr` with the decompiler (which recovers switch jump
  // tables) and returns every (BRANCHIND address, target) pair of the tables it found.
  rust::Vec<JumpEdgeOut> jump_tables(uint64_t addr);
  // Parses one C declaration (typedef, struct, union or enum) into the type factory.
  void declare_type(rust::Str decl);
  // Parses a C prototype such as `int printf(char *format,...)` and locks it onto the function
  // at `addr` (created when unknown), so call sites use its parameter and return types.
  void set_prototype(uint64_t addr, rust::Str decl);
  // Marks the function at `addr` (created when unknown) as never returning, or clears the mark.
  void set_noreturn(uint64_t addr, bool noreturn);
  // Removes the function symbol at `addr` (and with it any prototype); no-op when absent.
  void remove_function(uint64_t addr);
  // Sets the prototype model (calling convention) of the function at `addr` (created when
  // unknown) and locks it; an empty name restores the default model. Unknown names throw.
  void set_convention(uint64_t addr, rust::Str name);
  // Replaces the user comments of the function at `fad` with `comments` (each an address, a
  // decompiler comment type and the text). Warnings the decompiler adds are left alone.
  void set_comments(uint64_t fad, rust::Slice<const CommentIn> comments);

private:
  std::unique_ptr<Impl> impl;
};

// Builds a session for `language_id` + `compiler_id` (such as "gcc") over `image`.
std::unique_ptr<Session> new_session(rust::Str language_id, rust::Str compiler_id,
                                     rust::Box<ImageSource> image);

} // namespace kraken

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
  // Decodes up to `max` instructions starting at `addr`, stopping early at undecodable bytes.
  rust::Vec<InsnOut> decode(uint64_t addr, uint32_t max);
  // Raw p-code of the instructions in [start, end).
  rust::Vec<PcodeOpOut> lift(uint64_t start, uint64_t end);
  // Decompiles the function at `addr` (created with a default name when unknown).
  DecompOut decompile(uint64_t addr);
  // Follows the flow of the function at `addr` with the decompiler (which recovers switch jump
  // tables) and returns the targets of every jump table it found.
  rust::Vec<uint64_t> jump_targets(uint64_t addr);

private:
  std::unique_ptr<Impl> impl;
};

// Builds a session for `language_id` + `compiler_id` (such as "gcc") over `image`.
std::unique_ptr<Session> new_session(rust::Str language_id, rust::Str compiler_id,
                                     rust::Box<ImageSource> image);

} // namespace kraken

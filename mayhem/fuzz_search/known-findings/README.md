# fuzz_search known findings (upstream code, reachable from a UPnP ContentDirectory Search request)

Reproducers only. They are NOT seeds: Mayhem never reads this directory.

- `or-without-lhs/input` — `( or upnp:are contains "Hu") or upnp:artist exists true`.
  `SearchParser::parseParenthesis` builds an `ASTOrOperator` with a null `lhs` when `or`/`and` is the
  first token inside parentheses; `ASTOrOperator::emit` then calls `lhs->emit()` on null
  (`src/database/search_handler.cc:549`). Mayhem defect #3718154.
- `stray-token-hang/input` — the single byte `)`. In `SearchParser::parseSearchExpression` a top-level
  token that is not a property, `(`, `and` or `or` (`)`, a quoted string, a comparison operator, ...)
  matches no branch and never calls `getNextToken()`, so `while (currentToken)` loops forever
  (`src/database/search_handler.cc:198`). Short mutations hit it within a few hundred execs.

Reproduce: `/mayhem/fuzz_search-standalone <input>` (the hang: under `timeout`).

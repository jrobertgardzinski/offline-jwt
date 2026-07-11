# TODO — offline-jwt

- **Max-age na cache JWKS (luka w kill-switchu; właściciel spytał 2026-07-11).** Dziś refetch
  odpala się tylko na NIEZNANY `kid` — token sfałszowany skradzionym BIEŻĄCYM kluczem niesie
  znany `kid`, więc usunięcie skompromitowanego klucza z JWKS nie dociera do konsumentów aż do
  ich restartu. Fix: cache z max-age (np. 10–15 min) — wycofanie klucza propaguje w minuty,
  koszt to jeden GET na kwadrans na serwis. Przy okazji: verifier powinien tolerować JWKS
  z WIELOMA kluczami (overlap przy rotacji: nowy publikowany obok starego, stary wycofywany
  po max TTL access tokenu) — parsowanie już iteruje po `keys`, ale security serwuje dziś
  jeden klucz, więc overlap wymaga też zmiany po stronie mintu/JwksController.

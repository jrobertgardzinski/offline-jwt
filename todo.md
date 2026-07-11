# TODO — offline-jwt

- ~~**Max-age na cache JWKS (luka w kill-switchu; właściciel spytał 2026-07-11).**~~ ZROBIONE
  (2026-07-11): cache z max-age 15 min (konfigurowalne konstruktorem testowym z zegarem) —
  usunięcie skompromitowanego klucza z JWKS propaguje w minuty, nie przy restarcie konsumenta.
  Nieudany refetch NIE wyrzuca ostatnich dobrych kluczy (stale-while-error: niedostępny JWKS to
  incydent dostępności, nie rewokacja) i ponawia przy kolejnym żądaniu. 2 nowe testy (8/8).
- **Overlap kluczy przy rotacji** — verifier już toleruje JWKS z wieloma kluczami (iteruje po
  `keys`), ale security serwuje dziś jeden: poprawna rotacja (nowy klucz publikowany obok
  starego, stary wycofywany po max TTL access tokenu) wymaga zmiany po stronie
  mintu/JwksController w microservice-security.

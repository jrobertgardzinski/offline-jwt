# TODO — offline-jwt

- ~~**Max-age na cache JWKS (luka w kill-switchu; właściciel spytał 2026-07-11).**~~ ZROBIONE
  (2026-07-11): cache z max-age 15 min (konfigurowalne konstruktorem testowym z zegarem) —
  usunięcie skompromitowanego klucza z JWKS propaguje w minuty, nie przy restarcie konsumenta.
  Nieudany refetch NIE wyrzuca ostatnich dobrych kluczy (stale-while-error: niedostępny JWKS to
  incydent dostępności, nie rewokacja) i ponawia przy kolejnym żądaniu. 2 nowe testy (8/8).
- ~~**Overlap kluczy przy rotacji**~~ — ZROBIONE (2026-07-19, po stronie microservice-security,
  commit `3a3e4c1`): `security.jwt.previous-public-keys` (base64 X.509 po przecinku) trzyma
  publiczne połówki wycofanych kluczy w JWKS obok bieżącego, aż wygasną tokeny nimi podpisane —
  rotacja = czysta zmiana configu (nowa para do private/public-key, stary public na listę
  previous, zdjąć po max TTL access tokenu; prywatny klucz można zniszczyć od razu).
  Verifier bez zmian (wybiera po `kid`). Pin: `rotation_keeps_the_retired_key_in_the_jwks`;
  pakt JWKS zielony.

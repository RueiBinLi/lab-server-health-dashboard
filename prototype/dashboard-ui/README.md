# PROTOTYPE — Role-aware dashboard information architecture

Throwaway UI answering:

> Which overview and server-detail structure helps Lab Users compare Server Health and Resource Usage while giving Lab Administrators operational depth without overwhelming either role?

Three variants of a new dashboard surface, switchable with `?variant=`, live at one prototype route.

Run from the repository root:

```bash
python3 -m http.server 4173 --directory prototype/dashboard-ui
```

Then open:

- `http://localhost:4173/?variant=A&role=user`
- `http://localhost:4173/?variant=B&role=user`
- `http://localhost:4173/?variant=C&role=user`

Use the role control to compare Lab User and Lab Administrator disclosure. The bottom prototype bar or the left/right arrow keys switches variants.

This code is deliberately dependency-free, read-only, and disposable. Do not promote it directly into production.

# demo_skill

A tiny, harmless fixture used by the top-level [README](../../README.md)
quick-start. Declares only `filesystem.read`; `run.py` actually writes a
file and spawns a subprocess, so a dynamic audit shows those as
*undeclared observed* capabilities. This demonstrates the declared-vs-observed
comparison -- it does not indicate a real problem with this fixture.

```bash
skillguard audit examples/demo_skill \
  --capabilities examples/demo_skill/skillguard.capabilities.json \
  --dynamic -- python run.py
```

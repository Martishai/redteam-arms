"""Tests des agents : skills epitalab, taille des consignes, vérification d'Ollama, absence d'agno."""
import io
import json
import sys
import urllib.error

import pytest

import agents

SKILL = """---
name: ai-act-risk-classification
title: Test
description: |
  Use this skill when testing.
  Second line.
summary: "s"
---

Intro.

## Inputs to gather
Ask things.

## Step 1: confirm scope
Body one. More text.

## Step 2: rule out
Body two.

## What good looks like
- Good.

## Framework lookups
Publicité.
"""


def make_epitalab(root):
    skill = root / ".agents" / "skills" / "ai-act-risk-classification"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(SKILL, encoding="utf-8")
    (root / "Skills").mkdir()
    # Sous Windows, git extrait le lien symbolique Skills/<nom> en simple fichier texte.
    (root / "Skills" / "ai-act-risk-classification").write_text("../.agents/skills/ai-act-risk-classification")
    return skill.parent


def test_find_skills_dir_layouts(tmp_path):
    expected = make_epitalab(tmp_path / "EPITA" / "epitalab")
    deep = tmp_path / "EPITA" / "redteam-arms" / "redteam-arms"   # epitalab dans ../../
    flat = tmp_path / "EPITA" / "projet"                          # epitalab dans ../
    deep.mkdir(parents=True)
    flat.mkdir()
    assert agents.find_skills_dir(here=deep, env="") == expected
    assert agents.find_skills_dir(here=flat, env="") == expected
    assert agents.find_skills_dir(here=deep, env=str(tmp_path / "EPITA" / "epitalab")) == expected
    assert agents.find_skills_dir(here=deep, env=str(tmp_path / "EPITA" / "epitalab" / "Skills")) == expected
    assert agents.find_skills_dir(here=tmp_path / "ailleurs" / "x", env="") is None


def test_skill_digest_keeps_the_method():
    digest = agents.skill_digest(SKILL)
    assert digest.startswith("Objectif : Use this skill when testing. Second line.")
    assert "- Step 1: confirm scope : Body one. More text." in digest
    assert "Critères de qualité :\n- Good." in digest
    assert "Publicité" not in digest and "Ask things" not in digest


def test_load_skill_missing_returns_empty(tmp_path):
    assert agents.load_skill("inexistant", skills_dir=tmp_path) == ""


def test_instructions_fit_in_context(tmp_path, monkeypatch):
    big = ("---\ndescription: |\n  " + "x " * 400 + "\ntitle: t\n---\n"
           + "".join(f"## Step {i}: s\n" + "mot " * 300 + "\n" for i in range(1, 7))
           + "## What good looks like\n" + "- ok\n" * 50)
    for spec in agents.AGENTS.values():
        for name in spec["skills"]:
            (tmp_path / name).mkdir(exist_ok=True)
            (tmp_path / name / "SKILL.md").write_text(big, encoding="utf-8")
    monkeypatch.setattr(agents, "SKILLS_DIR", tmp_path)
    for key in agents.AGENTS:
        text = "\n".join(agents.instructions_for(key))
        assert "Grille de lecture GRC" in text
        assert len(text) < 12_000  # environ 3 500 tokens : laisse la place aux faits dans un contexte de 8192


@pytest.mark.parametrize("value, expected", [
    ("", "http://127.0.0.1:11434"),
    ("0.0.0.0", "http://127.0.0.1:11434"),
    ("localhost:11500", "http://localhost:11500"),
    ("http://serveur:11434/", "http://serveur:11434"),
])
def test_ollama_url(monkeypatch, value, expected):
    monkeypatch.setenv("OLLAMA_HOST", value)
    assert agents.ollama_url() == expected


class FakeOpener:
    def __init__(self, payload=None, error=None):
        self.payload, self.error = payload, error

    def open(self, url, timeout):
        if self.error:
            raise self.error
        return io.BytesIO(json.dumps(self.payload).encode())


def use_opener(monkeypatch, opener):
    monkeypatch.setattr(agents.urllib.request, "build_opener", lambda *a, **k: opener)
    monkeypatch.setattr(agents, "MODEL_ID", "qwen3:8b")


def test_check_ollama_down(monkeypatch):
    use_opener(monkeypatch, FakeOpener(error=urllib.error.URLError(ConnectionRefusedError("refusée"))))
    with pytest.raises(agents.AgentError, match="Ollama ne répond pas"):
        agents.check_ollama()


def test_check_ollama_model_missing(monkeypatch):
    use_opener(monkeypatch, FakeOpener({"models": [{"name": "llama3.1:latest"}]}))
    with pytest.raises(agents.AgentError, match="ollama pull qwen3:8b"):
        agents.check_ollama()


def test_check_ollama_ok(monkeypatch):
    use_opener(monkeypatch, FakeOpener({"models": [{"name": "qwen3:8b"}]}))
    agents.check_ollama()


def test_build_agent_without_agno(monkeypatch):
    monkeypatch.setitem(sys.modules, "agno", None)
    monkeypatch.setitem(sys.modules, "agno.agent", None)
    with pytest.raises(agents.AgentError, match="pip install -r requirements.txt"):
        agents.build_agent("reconnaissance")

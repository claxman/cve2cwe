"""The ablation subset is deterministic and the override files stay narrow."""

from cve2cwe.ablations import (
    ABLATION_NAMES,
    ablation_path,
    apply_override,
    load_override,
    load_train_config,
    sample_train_fraction,
)
from cve2cwe.prompts import REPO_ROOT


def test_same_seed_same_rows_and_tenth_is_rounded():
    rows = [{"cve_id": f"CVE-{i}"} for i in range(42291)]
    frac10 = load_override(ablation_path("frac10"))
    frac10_e6 = load_override(ablation_path("frac10-e6"))
    seed = int(frac10["fraction_seed"])
    first = sample_train_fraction(rows, float(frac10["train_fraction"]), seed)
    again = sample_train_fraction(rows, 0.10, seed)
    longer = sample_train_fraction(
        rows, float(frac10_e6["train_fraction"]), int(frac10_e6["fraction_seed"])
    )
    assert first == again
    assert first == longer
    assert len(first) == round(0.10 * len(rows))
    assert sample_train_fraction(rows, 0.10, seed + 1) != first


def test_override_files_only_change_the_named_knob():
    base, _ = load_train_config(None)
    assert [ablation_path(name).stem for name in ABLATION_NAMES] == list(ABLATION_NAMES)
    expected = {
        "frac05": {"run_tag", "train_fraction", "fraction_seed"},
        "frac10": {"run_tag", "train_fraction", "fraction_seed"},
        "frac30": {"run_tag", "train_fraction", "fraction_seed"},
        "frac10-e6": {"run_tag", "train_fraction", "fraction_seed", "num_train_epochs"},
        "r4": {"run_tag", "lora.r", "lora.alpha"},
        "r64": {"run_tag", "lora.r", "lora.alpha"},
        "qlora4bit": {"run_tag", "load_in_4bit", "load_in_16bit"},
    }
    for name in ABLATION_NAMES:
        path = ablation_path(name)
        merged, record = apply_override(base, load_override(path), path)
        assert record["path"] == f"configs/ablations/{name}.yaml"
        assert len(record["sha256"]) == 64
        changed = set()
        for key, value in merged.items():
            if key == "lora":
                for sub, sub_value in value.items():
                    if sub_value != base["lora"][sub]:
                        changed.add(f"lora.{sub}")
                continue
            if key not in base or value != base[key]:
                changed.add(key)
        assert changed == expected[name]
        assert merged["num_train_epochs"] == (6 if name == "frac10-e6" else 2)
        assert merged["lora"]["r"] == {"r4": 4, "r64": 64}.get(name, 16)
        assert merged["load_in_4bit"] is (name == "qlora4bit")
        assert path.is_relative_to(REPO_ROOT)

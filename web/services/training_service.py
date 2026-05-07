import os
import json
import subprocess
import threading
from datetime import datetime

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
TRAINING_STATE_FILE = os.path.join(PROJECT_DIR, "results", "training_state.json")
os.makedirs(os.path.join(PROJECT_DIR, "results"), exist_ok=True)


def load_training_state():
    if os.path.exists(TRAINING_STATE_FILE):
        with open(TRAINING_STATE_FILE) as f:
            return json.load(f)
    return {"running": False, "success": None, "stdout": "", "stderr": "",
            "started_at": None, "ended_at": None}


def save_training_state(state):
    with open(TRAINING_STATE_FILE, "w") as f:
        json.dump(state, f)


def run_training(cmd, cwd):
    state = {"running": True, "success": None, "stdout": "", "stderr": "",
             "started_at": datetime.now().isoformat(), "ended_at": None}
    save_training_state(state)
    try:
        _mpl_dir = os.path.join(PROJECT_DIR, "tmp", "matplotlib")
        os.makedirs(_mpl_dir, exist_ok=True)
        _train_env = os.environ.copy()
        _train_env.setdefault("MPLCONFIGDIR", _mpl_dir)
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=_train_env)
        state["success"] = result.returncode == 0
        state["stdout"] = result.stdout[-5000:]
        state["stderr"] = result.stderr[-1000:]
    except Exception as e:
        state["success"] = False
        state["stderr"] = str(e)
    finally:
        state["running"] = False
        state["ended_at"] = datetime.now().isoformat()
        save_training_state(state)

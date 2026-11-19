# Custom checks

Put an **executable** script in this folder (`sudo install -m 755 my-check.sh /home/notify/hub/checks/`).
It shows up on the hub's *Reports & checks* page, where you turn it on and choose when it runs.

Rules:

- Exit code **0**: all good. Nothing is sent (unless you tick "send the output even when it exits 0").
- Exit code **1**: alert at normal priority. Exit code **2 or higher**: high priority.
- What the script prints becomes the message. If the first line starts with `title:`, that line becomes the title.
- Runs as root with a 5-minute limit. Files ending in `.sample`, `.md` or `.txt` are ignored.

Example (`website-up.sh.sample` in this folder): copy it without `.sample`, make it executable, edit the URL.

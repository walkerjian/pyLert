# pyLert

Real-time network monitoring and alerting tool for macOS, inspired by Sysinternals/NirSoft

## Log Reader (log_reader.py)

To read and filter logs:

```sh
python src/log_reader.py --filter-process chrome --json
Options:

--filter-process (Filter by process name)
--filter-ip (Filter by specific IP)
--filter-date YYYY-MM-DD (Filter by date)
--json (Output in JSON format)
sql
Copy
Edit

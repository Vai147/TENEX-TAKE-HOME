"""VirusTotal threat-intel enrichment.

An on-demand layer that turns a stored upload's destination indicators (URL /
domain / IP) into VirusTotal reputation verdicts, raises SIEM-style alerts for the
malicious ones, and stays entirely off the synchronous ingest path so an external
outage or rate limit never touches an upload.
"""

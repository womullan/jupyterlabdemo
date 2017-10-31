"""
Put all the sections together.
"""
import os

# Set up auth environment
c.LSSTAuth.oauth_callback_url = os.environ['OAUTH_CALLBACK_URL']
c.LSSTAuth.client_id = os.environ['GITHUB_CLIENT_ID']
c.LSSTAuth.client_secret = os.environ['GITHUB_CLIENT_SECRET']
c.LSSTAuth.github_organization_whitelist = set(
    (os.environ['GITHUB_ORGANIZATION_WHITELIST'].split(",")))

# Listen to all interfaces
c.JupyterHub.ip = '0.0.0.0'
# Don't try to cleanup servers on exit - since in general for k8s, we want
# the hub to be able to restart without losing user containers
c.JupyterHub.cleanup_servers = False
# Set Hub IP explicitly
c.JupyterHub.hub_ip = os.environ['HUB_BIND_IP']
# Set Session DB URL if we have one
db_url = os.getenv('SESSION_DB_URL')
if db_url:
    c.JupyterHub.db_url = db_url

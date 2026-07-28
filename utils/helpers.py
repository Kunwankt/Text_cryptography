import base64
import csv
import io
from datetime import datetime


def format_timestamp(timestamp):
    """Format timestamp to human-readable string"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def export_history_to_csv(history):
    """Export history list to CSV string
    :param history: List of history dicts
    :return: CSV string
    """
    output = io.StringIO()
    fieldnames = ['id', 'algorithm', 'operation', 'timestamp']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for item in history:
        writer.writerow({
            'id': item.get('id'),
            'algorithm': item.get('algorithm'),
            'operation': item.get('operation'),
            'timestamp': format_timestamp(item.get('timestamp'))
        })
    return output.getvalue()

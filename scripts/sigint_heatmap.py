import sqlite3
import json
import logging
from datetime import datetime, timedelta
import os

logger = logging.getLogger("SIGINTHeatmap")

class SIGINTHeatmapGenerator:
    """
    Generates Geographic SIGINT Heatmaps based on correlated threats from multiple devices.
    This creates an HTML file that renders a Leaflet.js map with heatpoints where
    surveillance equipment (like IMSI catchers) has been detected by the remote server.
    """
    
    def __init__(self, db_path: str = "cellular_remote_monitoring.db", output_dir: str = "forensics/maps"):
        self.db_path = db_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
    def generate_heatmap(self, hours_back: int = 24) -> str:
        """Generate an HTML heatmap of threats in the last X hours."""
        if not os.path.exists(self.db_path):
            logger.error(f"[HEATMAP] Database not found at {self.db_path}")
            return ""
            
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cutoff_time = (datetime.now() - timedelta(hours=hours_back)).isoformat()
        
        cursor.execute('''
            SELECT threat_type, severity, latitude, longitude, timestamp 
            FROM threats 
            WHERE latitude IS NOT NULL AND longitude IS NOT NULL AND timestamp > ?
        ''', (cutoff_time,))
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            logger.info(f"[HEATMAP] No geo-tagged threats found in the last {hours_back} hours.")
            return ""
            
        heatpoints = []
        for r in rows:
            # Weight intensity by severity
            intensity = 1.0
            if r['severity'] == 'critical':
                intensity = 3.0
            elif r['severity'] == 'high':
                intensity = 2.0
                
            heatpoints.append([r['latitude'], r['longitude'], intensity])
            
        map_html = self._build_html(heatpoints, hours_back)
        
        filename = f"sigint_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(map_html)
            
        logger.info(f"[HEATMAP] Generated SIGINT Map: {filepath} with {len(heatpoints)} threat points.")
        return filepath
        
    def _build_html(self, points: list, hours: int) -> str:
        points_js = json.dumps(points)
        # Center map on the average of points, or default if empty
        if points:
            center_lat = sum(p[0] for p in points) / len(points)
            center_lon = sum(p[1] for p in points) / len(points)
        else:
            center_lat, center_lon = 0, 0
            
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Clutch SIGINT Heatmap (Last {hours}h)</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
    <style>
        body {{ margin: 0; padding: 0; font-family: monospace; background-color: #111; color: #0f0; }}
        #map {{ height: 90vh; width: 100vw; }}
        #header {{ height: 10vh; display: flex; align-items: center; padding-left: 20px; border-bottom: 2px solid #0f0; }}
    </style>
</head>
<body>
    <div id="header">
        <h2>🛡️ CLUTCH SIGINT HEATMAP - GEOGRAPHIC SURVEILLANCE CORRELATION (LAST {hours}H)</h2>
    </div>
    <div id="map"></div>
    <script>
        var map = L.map('map').setView([{center_lat}, {center_lon}], 13);
        L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 19
        }}).addTo(map);

        var heatPoints = {points_js};
        var heat = L.heatLayer(heatPoints, {{
            radius: 25,
            blur: 15,
            maxZoom: 17,
            gradient: {{0.4: 'blue', 0.6: 'lime', 0.8: 'yellow', 0.9: 'orange', 1.0: 'red'}}
        }}).addTo(map);
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    generator = SIGINTHeatmapGenerator()
    generator.generate_heatmap()

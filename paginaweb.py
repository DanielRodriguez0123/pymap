import subprocess

def generar_reporte_html(IP, PUERTOS_ABIERTOS, servicios_encontrados, vulns, recomendaciones, serviciosC):
    html_filename = f"reporte_{IP}.html"
    puertos = ', '.join(map(str, PUERTOS_ABIERTOS))
    servicios = ''.join(f"<li>{servicio}</li>" for servicio in servicios_encontrados)
    servicios_simplificados = ''.join(f"<li>{servicio}</li>" for servicio in serviciosC)
    # Filtrar vulnerabilidades generales
    vulnerabilidades_filtradas = [v for v in vulns if "CVE" not in v]
    vulnerabilidades_html = ''.join(f"<li>{vulnerabilidad}</li>" for vulnerabilidad in vulnerabilidades_filtradas)


    recomendaciones_html = ''
    for i, recomendacion in enumerate(recomendaciones):
        categoria = recomendacion.split(':')[0]
        detalle = ':'.join(recomendacion.split(':')[1:]).strip()
        recomendaciones_html += f"""
        <div class="recomendacion">
            <button class="accordion">{categoria}</button>
            <div class="panel">
                <p>{detalle}</p>
            </div>
        </div>
        """


    # Organizar CVEs por servicio
    cves_por_servicio = {}
    for vuln in vulns:
        if "CVE" in vuln:
            servicio_encontrado = False
            for servicio in serviciosC:
                if servicio.lower() in vuln.lower():
                    if servicio not in cves_por_servicio:
                        cves_por_servicio[servicio] = []
                    cves_por_servicio[servicio].append(vuln)
                    servicio_encontrado = True
                    break
            if not servicio_encontrado:
                if "Otros" not in cves_por_servicio:
                    cves_por_servicio["Otros"] = []
                cves_por_servicio["Otros"].append(vuln)

    cves_html = ""
    for servicio, cves in cves_por_servicio.items():
        cves_html += f"""
        <div class="cve-seccion">
            <button class="accordion">{servicio}</button>
            <div class="panel">
                <ul>
                    {"".join(f"<li>{cve}</li>" for cve in cves)}
                </ul>
            </div>
        </div>
        """

    # Filtrar y generar HTML para CVEs
    cves = [v for v in vulns if "CVE" in v]
    cves_html = f"""
    <div class="cve-seccion">
        <button class="accordion">CVEs</button>
        <div class="panel">
            <ul>
                {"".join(f"<li>{cve}</li>" for cve in cves)}
            </ul>
        </div>
    </div>
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Informe de Seguridad - {IP}</title>
        <style>
            body {{
                background-color: #0a0e14;
                color: #e6e6e6;
                font-family: 'Consolas', 'Courier New', monospace;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }}
            .container {{
                max-width: 1000px;
                margin: 0 auto;
                background-color: #141c2c;
                border-radius: 8px;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.1);
                overflow: hidden;
            }}
            header {{
                background-color: #1a2332;
                color: #00ff00;
                padding: 20px;
                text-align: center;
                border-bottom: 2px solid #00ff00;
            }}
            h1 {{
                margin: 0;
                font-size: 2.5em;
                text-transform: uppercase;
                letter-spacing: 2px;
            }}
            h2 {{
                color: #00ccff;
                border-bottom: 1px solid #00ccff;
                padding-bottom: 10px;
            }}
            .content {{
                padding: 20px;
            }}
            table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                margin-bottom: 20px;
            }}
            th, td {{
                border: 1px solid #2a3f5f;
                padding: 12px;
                text-align: left;
            }}
            th {{
                background-color: #1a2332;
                color: #00ccff;
                font-weight: bold;
                text-transform: uppercase;
            }}
            td {{
                background-color: #0f1620;
            }}
            .ip {{
                color: #ff3860;
                font-weight: bold;
            }}
            .ports {{
                color: #ffdd57;
            }}
            .services, .vulnerabilities, .recommendations {{
                color: #00ff00;
            }}
            ul {{
                list-style-type: none;
                padding-left: 0;
            }}
            li::before {{
                content: "\\25B6 ";
                color: #00ccff;
            }}
            .footer {{
                text-align: center;
                margin-top: 20px;
                font-size: 0.9em;
                color: #888;
            }}
            .accordion {{
                background-color: #1a2332;
                color: #00ccff;
                cursor: pointer;
                padding: 18px;
                width: 100%;
                text-align: left;
                border: none;
                outline: none;
                transition: 0.4s;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 1em;
            }}
            .active, .accordion:hover {{
                background-color: #2a3f5f;
            }}
            .panel {{
                padding: 0 18px;
                background-color: #0f1620;
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.2s ease-out;
            }}
            .cve-seccion {{
                margin-bottom: 10px;
            }}
            .cve-seccion .accordion {{
                background-color: #2a3f5f;
                color: #00ff00;
            }}
            .cve-seccion .panel {{
                background-color: #1a2332;
                padding: 10px;
            }}
            .cve-seccion ul {{
                margin: 0;
                padding-left: 20px;
            }}
            .cve-seccion li {{
                margin-bottom: 10px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Informe de Seguridad</h1>
            </header>
            <div class="content">
                <h2>Objetivo: <span class="ip">{IP}</span></h2>
                <table>
                    <tr>
                        <th>IP</th>
                        <th>Puertos Abiertos</th>
                        <th>Servicios</th>
                        <th>Servicios Simplificados</th>
                        <th>Vulnerabilidades</th>
                    </tr>
                    <tr>
                        <td class="ip">{IP}</td>
                        <td class="ports">{puertos}</td>
                        <td class="services"><ul>{servicios}</ul></td>
                        <td class="services"><ul>{servicios_simplificados}</ul></td>
                        <td class="vulnerabilities"><ul>{vulnerabilidades_html}</ul></td>
                    </tr>
                </table>
                <h2>CVEs Detectados</h2>
                <div class="cves">
                    {cves_html}
                </div>
                <h2>Recomendaciones</h2>
                <div class="recommendations">
                    {recomendaciones_html}
                </div>
            </div>
            <div class="footer">
                Generado por el Sistema Automatizado de Escaneo de Seguridad
            </div>
        </div>
         <script>
        var acc = document.getElementsByClassName("accordion");
        var i;

        for (i = 0; i < acc.length; i++) {{
            acc[i].addEventListener("click", function() {{
                this.classList.toggle("active");
                var panel = this.nextElementSibling;
                if (panel.style.maxHeight) {{
                    panel.style.maxHeight = null;
                }} else {{
                    panel.style.maxHeight = panel.scrollHeight + "px";
                }}
            }});
        }}
        </script>
    </body>
    </html>
    """


    with open(html_filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"Informe generado: {html_filename}")
    subprocess.run(['start', html_filename], shell=True, check=True)
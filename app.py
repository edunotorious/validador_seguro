from flask import Flask, request, render_template_string
from loguru import logger
import bleach
import re
import time
from collections import defaultdict

app = Flask(__name__)

# Setup do log
logger.add("logs.log", rotation="1 day", level="INFO")

# Armazena contagem por IP (simples)
tentativas_por_ip = defaultdict(int)
ultimos_acessos = defaultdict(float)

form_html = """
<!DOCTYPE html>
<html>
<head><title>Monitoramento</title></head>
<body>
    <h2>Formulário com Monitoramento</h2>
    <form method="post">
        Nome: <input type="text" name="nome"><br>
        Email: <input type="text" name="email"><br>
        Comentário: <textarea name="comentario"></textarea><br>
        <input type="submit" value="Enviar">
    </form>
    {% if alerta %}
        <h3 style="color:red">ALERTA: {{ alerta }}</h3>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    alerta = ""
    ip = request.remote_addr
    tentativas_por_ip[ip] += 1
    ultimos_acessos[ip] = time.time()

    nome = bleach.clean(request.form.get("nome", ""))
    email = bleach.clean(request.form.get("email", ""))
    comentario = bleach.clean(request.form.get("comentario", ""))

    logger.info(f"IP: {ip} | Nome: {nome} | Email: {email} | Comentário: {comentario}")

    # Detecção de padrões suspeitos
    if tentativas_por_ip[ip] > 5:
        alerta = f"Muitas tentativas do IP {ip}"
        logger.warning(alerta)

    if "<script>" in comentario.lower():
        alerta = "Tentativa de XSS detectada!"
        logger.warning(f"XSS detectado de {ip}: {comentario}")

    return render_template_string(form_html, alerta=alerta)

if __name__ == "__main__":
    app.run(debug=True)

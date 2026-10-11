<div align="center">

# 🎯 Pro Labs · Red Team & Active Directory

<img src="https://readme-typing-svg.demolab.com/?font=Fira+Code:wght@500&size=20&pause=1000&color=F7931E&center=true&vCenter=true&width=620&lines=C2+%E2%86%92+Active+Directory+%E2%86%92+Lateral+Movement;Sliver+%C2%B7+Mythic+%C2%B7+PrintNightmare+%C2%B7+DevOps;Assumed+Breach+%C2%B7+Pivoting+%C2%B7+Post-explotaci%C3%B3n" alt="Typing SVG" />

</div>

Portafolio de **Pro Labs** (entornos multi-máquina de Hack The Box / VulnLab) documentados como **engagement real**: operación a través de un framework **C2**, ataques a **Active Directory**, pivoting, escalada de privilegios y post-explotación.

Los writeups se organizan **por dificultad** en tres niveles.

---

## 📊 Niveles de dificultad

| Nivel | Carpeta | Descripción |
|:--:|---|---|
| 🟢 **Básico** | [`Basico/`](Basico) | Cadenas cortas (1–2 hosts), técnicas fundamentales, menor profundidad de pivoting |
| 🟠 **Intermedio** | [`Intermedio/`](Intermedio) | Entornos AD híbridos, C2, movimiento lateral, 2–4 hosts |
| 🔴 **Avanzado** | [`Avanzado/`](Avanzado) | Bosques múltiples, evasión, cadenas largas y operación compleja |

> La clasificación sigue el criterio de la plataforma (dificultad oficial) ajustada por **profundidad técnica de la cadena** documentada.

---

## 🧪 Labs documentados

| Lab | Nivel | Hosts | C2 | Cadena | Writeup |
|:--|:--:|:--|:--:|:--|:--:|
| **Puppet** | 🟠 Intermedio | `PUPPET-PM01` · `FILE01` · `DC01` | Sliver | FTP → Sliver → PrintNightmare → Puppet code exec → DC01 → SharpDPAPI | 📄 [Abrir](Intermedio/Puppet/README.md) |

---

## 📁 Estructura del repositorio

```text
Pro-Labs/
├── Avanzado/        # Labs de dificultad alta
├── Intermedio/      # Labs de dificultad media
│   └── Puppet/      # Sliver C2 · Active Directory · DevOps abuse
│       ├── README.md
│       └── screenshots/
└── Basico/          # Labs de dificultad baja
```

---

## 🧠 Cómo está escrito cada writeup

Estructura fija, para seguir la cadena de ataque y entender el razonamiento:

```text
0. Resumen ejecutivo       → la cadena, el "quién, cómo y desde dónde"
1. Recon / Acceso inicial  → superficie y primeras decisiones
2..N. Cadena de ataque     → cada paso con comandos, salidas reales y las PISTAS
Anexo A. Intentos fallidos → lo que NO funcionó y por qué (la parte valiosa)
Anexo B. Indicadores       → hosts, credenciales (enmascaradas), CVEs, herramientas
Anexo C. Cronología        → el ataque de un vistazo (ASCII)
```

**Principio:** cada paso incluye **qué** se ejecutó, **por qué** funciona y **qué pista** del entorno llevó al siguiente.

---

## 🛡️ Política de divulgación

Solo se documentan labs **retirados** o con permiso expreso de la plataforma. En la versión pública **flags, contraseñas y claves van enmascaradas** para no afectar a quien esté resolviendo el entorno. Los procedimientos, comandos y evidencia quedan íntegros.

---

<div align="center">

### `C2 → AD Enum → Lateral Movement → Privesc → Domain`

**kur0s4k1** · Red Team Operator · [GitHub](https://github.com/kur0s4k1)

</div>
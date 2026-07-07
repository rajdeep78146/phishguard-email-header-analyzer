const API_URL =
    window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost"
        ? "http://127.0.0.1:5000/analyze"
        : "/analyze";
async function analyze() {
    const header = document.getElementById('headerBox').value;

    if (!header.trim()) {
        alert("Please paste a header!");
        return;
    }

    document.getElementById('loader').classList.remove('hidden');
    document.getElementById('resultArea').classList.add('hidden');

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ header })
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.error || "Invalid header input");
            return;
        }

        display(data);

    } catch (e) {
        alert("Error connecting to server! Make sure python app.py is running.");
    } finally {
        document.getElementById('loader').classList.add('hidden');
    }
}

function display(res) {
    document.getElementById('resultArea').classList.remove('hidden');
    document.getElementById('verdictText').innerText = res.verdict;
    document.getElementById('scoreText').innerText = res.score;
    
    // UI Color based on verdict
    const color = res.score > 70 ? "#fb7185" : res.score > 30 ? "#fbbf24" : "#4ade80";
    document.getElementById('verdictText').style.color = color;

    document.getElementById('infoList').innerHTML = `
        <p><b>From:</b> ${res.data.from}</p>
        <p><b>Reply-To:</b> ${res.data.reply_to || 'N/A'}</p>
        <p><b>Hops:</b> ${res.data.hops}</p>
        <p><b>SPF in DNS:</b> ${res.dns.spf}</p>
    `;

    document.getElementById('flagList').innerHTML = res.findings.length > 0 
        ? res.findings.map(f => `<li>${f}</li>`).join('')
        : "<li style='color:#4ade80'>No critical red flags detected.</li>";
}

function clearAll() {
    document.getElementById('headerBox').value = "";
    document.getElementById('resultArea').classList.add('hidden');
    document.getElementById('loader').classList.add('hidden');
}
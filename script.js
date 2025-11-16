async function checkURL() {
    let url = document.getElementById("urlInput").value.trim();

    if (url === "") {
        alert("Masukkan link dulu!");
        return;
    }

    // Animasi loading
    let scanBtn = document.getElementById("scanBtn");
    scanBtn.innerHTML = <div class="loader"></div>;
    scanBtn.disabled = true;

    // Pastikan URL valid
    if (!url.startsWith("http")) {
        url = "https://" + url;
    }

    let resultBox = document.getElementById("result");
    let analysisBox = document.getElementById("analysis");
    let detailTitle = document.getElementById("detailTitle");

    // Parsing domain
    let domain;
    try {
        domain = new URL(url).hostname;
    } catch {
        resultBox.className = "result danger fade-in";
        resultBox.innerText = "❌ Link tidak valid!";
        resetButton();
        return;
    }

    // ===========================
    // ANALISIS LOKAL
    ===========================
    const suspiciousWords = ["free", "gift", "hadiah", "reward", "bonus", "claim", "login", "verify", "undian"];
    const httpUsed = url.startsWith("http://");
    const longURL = url.length > 80;
    const manySubdomains = domain.split(".").length >= 4;
    const weirdChars = /[%@#&*!]/.test(url);
    const scamWords = suspiciousWords.some(w => url.toLowerCase().includes(w));
    const fakeGoogle = domain.includes("go0gle") || domain.includes("g00gle");

    let score = 100;
    if (httpUsed) score -= 30;
    if (longURL) score -= 20;
    if (manySubdomains) score -= 20;
    if (weirdChars) score -= 10;
    if (scamWords) score -= 25;
    if (fakeGoogle) score -= 40;

    // ===========================
    // ANALISIS API VIRUSTOTAL
    ===========================
    let vtStatus = "Tidak tersedia";
    let vtDanger = false;

    try {
        const apiKey = "YOUR_API_KEY_HERE"; // ← Masukkan API Key di sini

        // Step 1: Kirim URL ke VirusTotal
        let upload = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: { "x-apikey": apiKey },
            body: new URLSearchParams({ url })
        });

        let uploadData = await upload.json();
        let analysisId = uploadData.data.id;

        // Step 2: Ambil hasil analisis
        let analysis = await fetch(
            https://www.virustotal.com/api/v3/analyses/${analysisId},
            { headers: { "x-apikey": apiKey } }
        );

        let result = await analysis.json();

        let stats = result.data.attributes.stats;

        if (stats.malicious > 0 || stats.suspicious > 0) {
            vtStatus = Berbahaya (${stats.malicious} malicious, ${stats.suspicious} suspicious);
            vtDanger = true;
            score -= 40;
        } else {
            vtStatus = "Aman oleh VirusTotal";
        }

    } catch (err) {
        console.log("VirusTotal API error:", err);
        vtStatus = "API Error / Limit Tercapai";
    }

    // ===========================
    // HASIL AKHIR
    // ===========================
    let status = "";
    let statusClass = "";

    if (score >= 80) {
        status = "✔ Aman • Resiko Rendah";
        statusClass = "safe";
    } else if (score >= 50) {
        status = "⚠ Waspada • Bisa Berpotensi Penipuan";
        statusClass = "warning";
    } else {
        status = "❌ Bahaya Tinggi • Sangat Mirip Link Phishing";
        statusClass = "danger";
    }

    resultBox.className = result ${statusClass} fade-in;
    resultBox.innerText = status;

    // ===========================
    // DETAIL OUTPUT LENGKAP
    // ===========================
    analysisBox.classList.remove("hide");
    detailTitle.classList.remove("hide");

    analysisBox.innerHTML = `
        <div class="item"><b>Domain:</b> ${domain}</div>
        <div class="item"><b>Analisis VirusTotal:</b> ${vtStatus}</div>
        <div class="item"><b>Menggunakan HTTP:</b> ${httpUsed ? "Ya (Bahaya)" : "Tidak (Aman)"}</div>
        <div class="item"><b>URL Panjang:</b> ${longURL ? "Ya" : "Tidak"}</div>
        <div class="item"><b>Banyak Subdomain:</b> ${manySubdomains ? "Ya" : "Tidak"}</div>
        <div class="item"><b>Karakter Aneh:</b> ${weirdChars ? "Ya" : "Tidak"}</div>
        <div class="item"><b>Kata-kata Scam:</b> ${scamWords ? "Mengandung kata mencurigakan" : "Tidak ada"}</div>
        <div class="item"><b>Palsu Meniru Google:</b> ${fakeGoogle ? "Ya" : "Tidak"}</div>
        <div class="item"><b>Skor Akhir:</b> ${score}/100</div>
    `;

    // Reset tombol setelah scan selesai
    resetButton();
}

// =========================
// FUNGSI RESET TOMBOL SCAN
// =========================
function resetButton() {
    let scanBtn = document.getElementById("scanBtn");
    scanBtn.innerHTML = "Scan Link";
    scanBtn.disabled = false;
}
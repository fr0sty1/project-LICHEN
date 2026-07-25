// Spectrum waterfall and TDMA visualization
(function() {
  const canvas = document.getElementById('spectrum');
  const ctx = canvas.getContext('2d');
  let t = 0;

  function drawSpectrum() {
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, 800, 160);

    for (let x = 0; x < 800; x += 4) {
      const intensity = Math.sin(t / 10 + x / 50) * 40 + 80 + Math.random() * 20;
      const hue = (x / 8) % 360;
      ctx.fillStyle = `hsl(${hue}, 80%, ${intensity}%)`;
      ctx.fillRect(x, 0, 4, 160);
    }

    // Overlay LICHEN channel and TDMA slots
    ctx.fillStyle = 'rgba(0,255,100,0.3)';
    ctx.fillRect(200, 0, 80, 160);  // active channel

    ctx.strokeStyle = '#0f0';
    ctx.lineWidth = 2;
    for (let s = 0; s < 8; s++) {
      const y = 20 + (t % 160);
      ctx.beginPath();
      ctx.moveTo(50 + s * 90, y);
      ctx.lineTo(120 + s * 90, y + 20);
      ctx.stroke();
    }

    t += 3;
    requestAnimationFrame(drawSpectrum);
  }

  drawSpectrum();
})();

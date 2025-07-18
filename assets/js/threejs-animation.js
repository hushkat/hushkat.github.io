document.addEventListener('DOMContentLoaded', function() {
  console.log('Three.js script loaded');
  
  // Add the container
  const container = document.createElement('div');
  container.id = 'threejs-bg';
  document.body.appendChild(container);
  
  // Load Three.js and run animation
  const script = document.createElement('script');
  script.src = 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js';
  script.onload = function() {
    console.log('Three.js loaded');
    
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.1, 1000);
    camera.position.z = 3;
    
    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: false
    });
    renderer.setClearColor(0x001122, 1);
    renderer.setSize(window.innerWidth, window.innerHeight);
    container.appendChild(renderer.domElement);
    
    const geometry = new THREE.IcosahedronGeometry(1, 1);
    const material = new THREE.MeshBasicMaterial({
      color: 0x1DB954,
      wireframe: true,
      wireframeLinewidth: 2
    });
    const mesh = new THREE.Mesh(geometry, material);
    scene.add(mesh);
    
    function animate() {
      requestAnimationFrame(animate);
      mesh.rotation.x += 0.005;
      mesh.rotation.y += 0.008;
      renderer.render(scene, camera);
    }
    animate();
    
    window.addEventListener('resize', () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    });
  };
  document.head.appendChild(script);
});

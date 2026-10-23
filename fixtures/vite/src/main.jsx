import React from 'react';import{createRoot}from'react-dom/client';import {marker} from './shared.js';import './style.css';
function App(){const[status,setStatus]=React.useState('waiting');async function load(){const x=await import('./lazy.js');setStatus(x.lazyMessage)}return <main><h1 id="pof-header">Vite React: {marker}</h1><button id="pof-load" onClick={load}>Load dynamic chunk</button><p id="pof-status">{status}</p><img id="pof-img" src="/pixel.png" /></main>}
createRoot(document.getElementById('root')).render(<App/>);

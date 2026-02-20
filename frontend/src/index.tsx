import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Import cyber fonts (from @fontsource packages)
import '@fontsource/orbitron/400.css';
import '@fontsource/orbitron/500.css';
import '@fontsource/orbitron/600.css';
import '@fontsource/orbitron/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';

// Global styles
const globalStyles = `
  * {
    box-sizing: border-box;
  }

  html {
    scroll-behavior: smooth;
  }

  body {
    margin: 0;
    padding: 0;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    background-color: #0a0a0a;
    color: #e4e4e7;
  }

  /* Scrollbar styling for cyber aesthetic */
  ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
  }

  ::-webkit-scrollbar-track {
    background: #111827;
  }

  ::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, #00ffff 0%, #00d4ff 100%);
    border-radius: 4px;
  }

  ::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(180deg, #00ffff 0%, #ff00ff 100%);
  }

  /* Focus styles for accessibility */
  :focus-visible {
    outline: 2px solid #00ffff;
    outline-offset: 2px;
  }

  /* Selection styles */
  ::selection {
    background-color: rgba(0, 255, 255, 0.3);
    color: #ffffff;
  }
`;

// Inject global styles
const styleElement = document.createElement('style');
styleElement.textContent = globalStyles;
document.head.appendChild(styleElement);

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

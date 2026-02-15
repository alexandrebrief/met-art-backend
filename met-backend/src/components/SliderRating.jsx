import React, { useState, useEffect } from 'react';

const SliderRating = ({ value, onChange, label }) => {
  const [sliderValue, setSliderValue] = useState(value);

  useEffect(() => {
    setSliderValue(value);
  }, [value]);

  const handleChange = (e) => {
    const rawValue = parseFloat(e.target.value);
    const roundedValue = Math.round(rawValue * 2) / 2;
    setSliderValue(roundedValue);
  };

  const handleMouseUp = () => {
    onChange(sliderValue);
  };

  const percentage = (sliderValue / 5) * 100;

  const markers = [];
  for (let i = 0; i <= 10; i++) {
    markers.push(i * 0.5);
  }

  return (
    <div style={{ 
      display: 'flex', 
      alignItems: 'center', 
      gap: '0.75rem',
      width: '100%',
      marginBottom: '0.6rem'
    }}>
      {/* Label */}
      <span style={{ 
        width: '70px', 
        fontSize: '0.8rem',
        fontWeight: '500',
        color: 'var(--text-light)'
      }}>
        {label}
      </span>
      
      {/* Slider */}
      <div style={{ 
        position: 'relative',
        flex: 1,
        height: '30px',
        display: 'flex',
        alignItems: 'center'
      }}>
        {/* Ligne de fond */}
        <div style={{
          position: 'absolute',
          width: '100%',
          height: '4px',
          backgroundColor: 'rgba(255,255,255,0.2)',
          borderRadius: '2px',
          top: '50%',
          transform: 'translateY(-50%)'
        }} />
        
        {/* Partie remplie */}
        <div style={{
          position: 'absolute',
          width: `${percentage}%`,
          height: '4px',
          backgroundColor: 'var(--accent)',
          borderRadius: '2px',
          top: '50%',
          transform: 'translateY(-50%)'
        }} />
        
        {/* Marqueurs */}
        {markers.map((marker) => (
          <div
            key={marker}
            style={{
              position: 'absolute',
              left: `${(marker / 5) * 100}%`,
              width: '2px',
              height: '8px',
              backgroundColor: marker <= sliderValue ? 'var(--accent)' : 'rgba(255,255,255,0.3)',
              top: '50%',
              transform: 'translate(-50%, -50%)',
              borderRadius: '1px'
            }}
          />
        ))}
        
        {/* Curseur fin */}
        <div
          style={{
            position: 'absolute',
            left: `${percentage}%`,
            width: '3px',
            height: '16px',
            backgroundColor: 'white',
            top: '50%',
            transform: 'translate(-50%, -50%)',
            borderRadius: '1px',
            boxShadow: '0 2px 4px rgba(0,0,0,0.3)',
            pointerEvents: 'none'
          }}
        />
        
        {/* Input invisible */}
        <input
          type="range"
          min="0"
          max="5"
          step="0.1"
          value={sliderValue}
          onChange={handleChange}
          onMouseUp={handleMouseUp}
          onTouchEnd={handleMouseUp}
          style={{
            position: 'absolute',
            width: '100%',
            height: '30px',
            opacity: 0,
            cursor: 'pointer',
            zIndex: 10
          }}
        />
      </div>
      
      {/* Valeur - PLUS PETITE */}
      <span style={{
        fontSize: '0.65rem',    // ← Plus petit
        fontWeight: '300',
        color: 'var(--text-light)',
        minWidth: '45px',
        textAlign: 'right'
      }}>
        {sliderValue.toFixed(1)} / 5
      </span>
    </div>
  );
};

export default SliderRating;

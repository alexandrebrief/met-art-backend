// src/components/Rating.jsx
import React, { useState } from 'react';

const Rating = ({ value, onChange, size = 'medium', interactive = true }) => {
  const [hoverValue, setHoverValue] = useState(null);

  const handleStarClick = (index, isHalf) => {
    if (!interactive) return;
    let newValue;
    if (isHalf) {
      newValue = index + 0.5;
    } else {
      newValue = index + 1;
    }
    // Si on clique sur la même valeur, on met à 0
    if (newValue === value) {
      onChange(0);
    } else {
      onChange(newValue);
    }
  };

  const handleMouseMove = (e, index) => {
    if (!interactive) return;
    const { left, width } = e.currentTarget.getBoundingClientRect();
    const percent = (e.clientX - left) / width;
    if (percent <= 0.5) {
      setHoverValue(index + 0.5);
    } else {
      setHoverValue(index + 1);
    }
  };

  const handleMouseLeave = () => {
    if (!interactive) return;
    setHoverValue(null);
  };

  const getStarContent = (index) => {
    const displayValue = hoverValue !== null && interactive ? hoverValue : value;
    const starValue = index + 1;
    
    if (displayValue >= starValue) {
      return '★'; // Pleine
    } else if (displayValue >= starValue - 0.5) {
      return '½'; // Demie
    } else {
      return '☆'; // Vide
    }
  };

  const getStarColor = (index) => {
    const displayValue = hoverValue !== null && interactive ? hoverValue : value;
    const starValue = index + 1;
    
    if (displayValue >= starValue) {
      return '#c49a6c';
    } else if (displayValue >= starValue - 0.5) {
      return '#c49a6c';
    } else {
      return '#ddd';
    }
  };

  const starSize = size === 'large' ? '32px' : size === 'small' ? '20px' : '24px';

  return (
    <div style={styles.container}>
      <div style={styles.stars}>
        {[0, 1, 2, 3, 4].map((index) => (
          <span
            key={index}
            onMouseMove={(e) => interactive && handleMouseMove(e, index)}
            onMouseLeave={handleMouseLeave}
            onClick={() => interactive && handleStarClick(index, hoverValue === index + 0.5)}
            style={{
              ...styles.star,
              fontSize: starSize,
              color: getStarColor(index),
              cursor: interactive ? 'pointer' : 'default'
            }}
          >
            {getStarContent(index)}
          </span>
        ))}
      </div>
      {interactive && value > 0 && (
  <span style={{
    fontSize: '0.85rem',
    fontWeight: '600',
    color: 'var(--accent)'
  }}>
    {value.toFixed(1)} / 5
  </span>
)}
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  stars: {
    display: 'flex',
    gap: '0.25rem'
  },
  star: {
    transition: 'color 0.2s'
  },
  value: {
    fontSize: '0.8rem',
    color: '#666',
    fontWeight: '500'
  }
};

export default Rating;

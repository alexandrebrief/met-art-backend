// src/components/Rating.jsx
import React, { useState } from 'react';

const Rating = ({ value, onChange, size = 'medium', interactive = true }) => {
  const [hoverValue, setHoverValue] = useState(null);

  const handleMouseMove = (e, index) => {
    if (!interactive) return;
    const { left, width } = e.currentTarget.getBoundingClientRect();
    const percent = (e.clientX - left) / width;
    // 0.5 incréments
    const newValue = percent <= 0.25 ? index : 
                     percent <= 0.75 ? index + 0.5 : index + 1;
    setHoverValue(Math.min(5, Math.max(0, newValue)));
  };

  const handleClick = () => {
    if (!interactive || hoverValue === null) return;
    onChange(hoverValue);
  };

  const getStarStyle = (index) => {
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
      return '#ffd700';
    } else if (displayValue >= starValue - 0.5) {
      return '#ffd700';
    } else {
      return '#ccc';
    }
  };

  const starSize = size === 'large' ? '32px' : size === 'small' ? '20px' : '24px';

  return (
    <div style={styles.container}>
      <div style={styles.stars}>
        {[0, 1, 2, 3, 4].map((index) => (
          <span
            key={index}
            onMouseMove={(e) => handleMouseMove(e, index)}
            onMouseLeave={() => interactive && setHoverValue(null)}
            onClick={handleClick}
            style={{
              ...styles.star,
              fontSize: starSize,
              color: getStarColor(index),
              cursor: interactive ? 'pointer' : 'default'
            }}
          >
            {getStarStyle(index)}
          </span>
        ))}
      </div>
      {interactive && (
        <span style={styles.value}>
          {value ? value.toFixed(1) : '0'} / 5
        </span>
      )}
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem'
  },
  stars: {
    display: 'flex',
    gap: '0.25rem'
  },
  star: {
    transition: 'color 0.2s'
  },
  value: {
    fontSize: '0.9rem',
    color: '#666',
    fontWeight: '500'
  }
};

export default Rating;

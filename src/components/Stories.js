import React from 'react';

function Stories() {
    return (
        <div className="d-flex mb-3">
            {[1, 2, 3, 4, 5].map((n) => (
                <div
                    key={n}
                    className="me-2"
                    style={{
                        width: 110,
                        height: 180,
                        background: '#fff',
                        borderRadius: 12,
                        overflow: 'hidden',
                        boxShadow: '0 2px 8px rgba(0,0,0,0.07)',
                        position: 'relative',
                    }}
                >
                    <img
                        src={`https://randomuser.me/api/portraits/men/1${n}.jpg`}
                        alt="Story"
                        style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                    />
                    <img
                        src={`https://randomuser.me/api/portraits/men/1${n}.jpg`}
                        alt="User"
                        className="rounded-circle border border-2 border-primary"
                        style={{
                            width: 36,
                            height: 36,
                            position: 'absolute',
                            bottom: 8,
                            left: 8,
                        }}
                    />
                </div>
            ))}
        </div>
    );
}

export default Stories;

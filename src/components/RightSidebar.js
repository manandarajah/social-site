import React from 'react';

function RightSidebar() {
  return (
    <div className="col-3 d-none d-lg-block">
      <div className="card border-0 bg-transparent">
        <div className="card-body">
          <h6 className="fw-bold mb-3">Contacts</h6>
          {[11, 12, 13, 14, 15].map((n) => (
            <div className="d-flex align-items-center mb-2" key={n}>
              <img
                src={`https://randomuser.me/api/portraits/women/${n}.jpg`}
                alt="Contact"
                className="rounded-circle me-2"
                width="32"
                height="32"
              />
              <span>Jane {n}</span>
              <span className="ms-auto text-success" style={{ fontSize: '0.8rem' }}>
                <i className="bi bi-circle-fill"></i>
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default RightSidebar;

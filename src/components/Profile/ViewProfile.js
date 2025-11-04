import React from 'react';

function ViewProfile(props) {
    const profile = props.profile;

    return (
        <div>
            <div className="d-flex flex-column align-items-center mb-4">
                <img
                    src={profile.profile_picture}
                    alt="Profile"
                    className="rounded-circle mb-3"
                    width="120"
                    height="120"
                    style={{ objectFit: 'cover', border: '3px solid #1877f2' }}
                />
                <h3 className="fw-bold mb-1">
                    {profile.first_name} {profile.last_name}
                </h3>
                {profile.current_user && (
                    <div className="text-muted">
                        {profile.email}
                    </div>
                )}
            </div>
            <hr />
            {profile.current_user && (
                <div className="row mb-2">
                    <div className="col-5 fw-semibold">Password:</div>
                </div>
            )}
            {[
                { label: "Username", value: profile.username, key: "username" },
                { label: "Gender", value: profile.gender, key: "gender" },
                { label: "Sexuality", value: profile.sexuality, key: "sexuality" },
                { label: "Birthday", value: profile.birthday, key: "birthday" },
                { label: "Height", value: profile.height, key: "height" },
                { label: "Weight", value: profile.weight, key: "weight" },
                { label: "Body Type", value: profile.body_type, key: "body_type" },
            ].map(field => (
                <div className="row mb-2" key={field.key}>
                    <div className="col-5 fw-semibold">{field.label}:</div>
                    <div className="col-7 d-flex align-items-center">
                        {field.value}
                    </div>
                </div>
            ))}
        </div>
    );
}

export default ViewProfile;

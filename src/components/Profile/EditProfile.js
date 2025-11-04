import React, { useState } from 'react';

function EditProfile(props) {
    const profile = props.profile;
    const csrf_token = props.get_cookie();
    const [removePictureUpload, setRemovePictureUpload] = React.useState("btn btn-light d-flex align-items-center ");
    const [removeRadioButton, setRemoveRadioButton] = React.useState(profile.profile_picture || "d-none");

    // Use React state to manage form fields for editing profile

    // Initialize state for each field
    const [formData, setFormData] = useState({
        profile_picture: profile.profile_picture || "",
        username: profile.username || "",
        email: profile.email || "",
        first_name: profile.first_name || "",
        last_name: profile.last_name || "",
        gender: profile.gender || "",
        sexuality: profile.sexuality || "",
        birthday: profile.birthday || "",
        height: profile.height || "",
        weight: profile.weight || "",
        body_type: profile.body_type || "",
        password: "",
        confirm_password: ""
    });

    if (!profile) {
        return (
            <div className="container mt-5">
                <div className="alert alert-warning text-center">No profile data found.</div>
            </div>
        );
    }

    // Handle input changes
    const handleChange = (e) => {
        const { name, value, type, files } = e.target;
        if (type === "file") {
            setFormData(prev => ({
                ...prev,
                [name]: files[0]
            }));
        } else {
            setFormData(prev => ({
                ...prev,
                [name]: value
            }));
        }
    };

    return (
        <form method='POST' action='/update-account' enctype='multipart/form-data'>
            <div className="d-flex flex-column align-items-center mb-4">
                <input type="file" className={removePictureUpload} onChange={() => setRemoveRadioButton("d-none")} name="profile_picture" />
                <span className={removeRadioButton}>Remove Profile Picture<input type="radio" onClick={() => setRemovePictureUpload("d-none")} name="remove_profile_picture" value="remove" /></span>
                Username: <input type="text" class="form-control" pattern="^[A-Za-z0-9]+$" name="username" onChange={handleChange} placeholder="Enter username" value={formData.username} required />
                Email: <input type="email" class="form-control" name="email" onChange={handleChange} placeholder="Enter email" value={formData.email} required />
            </div>
            <hr />
            {profile.current_user && (
                <div className="row mb-2">
                    <div className="col-5 fw-semibold">Password:</div>
                    <div className="col-7 d-flex align-items-center">
                        <input type="password" class="form-control" pattern="(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|\\;:',.<>\/?]).{8,}" name="password" placeholder="Password" />
                    </div>
                    <div className="col-5 fw-semibold">Confirm Password:</div>
                    <div className="col-7 d-flex align-items-center">
                        <input type="password" class="form-control" pattern="(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|\\;:',.<>\/?]).{8,}" name="confirm_password" placeholder="Password" />
                    </div>
                </div>
            )}
            {[
                { label: "First Name", input_type: "text", pattern: "^[A-Za-z0-9]+$", value: formData.first_name, key: "first_name" },
                { label: "Last Name", input_type: "text", pattern: "^[A-Za-z0-9]+$", value: formData.last_name, key: "last_name" },
                { label: "Gender", input_type: "select", value: formData.gender, key: "gender" },
                { label: "Sexuality", input_type: "select", value: formData.sexuality, key: "sexuality" },
                { label: "Birthday", input_type: "date", pattern: "", value: formData.birthday, key: "birthday" },
                { label: "Height", input_type: "number", pattern: "", value: formData.height, key: "height" },
                { label: "Weight", input_type: "number", pattern: "", value: formData.weight, key: "weight" },
                { label: "Body Type", input_type: "select", value: formData.body_type, key: "body_type" },
            ].map(field => (
                <div className="row mb-2" key={field.key}>
                    <div className="col-5 fw-semibold">{field.label}:</div>
                    <div className="col-7 d-flex align-items-center">
                        {field.input_type === "select" && (
                            <div>
                                {field.key === "gender" && (
                                    <select class="form-select" name="gender" onChange={handleChange}>
                                        <option value="" disabled selected>Select gender</option>
                                        <option value="male">Male</option>
                                        <option value="female">Female</option>
                                        <option value="nonbinary">Non-binary</option>
                                        <option value="other">Other</option>
                                        <option value="prefer_not_say">Prefer not to say</option>
                                    </select>
                                )}
                                {field.key === "sexuality" && (
                                    <select class="form-select" name="sexuality" onChange={handleChange}>
                                        <option value="" disabled selected>Select sexuality</option>
                                        <option value="straight">Straight</option>
                                        <option value="gay">Gay</option>
                                        <option value="lesbian">Lesbian</option>
                                        <option value="bisexual">Bisexual</option>
                                        <option value="asexual">Asexual</option>
                                        <option value="pansexual">Pansexual</option>
                                        <option value="queer">Queer</option>
                                        <option value="other">Other</option>
                                        <option value="prefer_not_say">Prefer not to say</option>
                                    </select>
                                )}
                                {field.key === "body_type" && (
                                    <select class="form-select" name="body_type" onChange={handleChange}>
                                        <option value="" disabled selected>Select body type</option>
                                        <option value="slim">Slim</option>
                                        <option value="average">Average</option>
                                        <option value="athletic">Athletic</option>
                                        <option value="curvy">Curvy</option>
                                        <option value="muscular">Muscular</option>
                                        <option value="plus_size">Plus Size</option>
                                        <option value="other">Other</option>
                                    </select>
                                )}
                            </div>
                        )}
                        {field.input_type !== "select" && (
                            <span>
                                <input type={field.input_type} class="form-control" pattern={field.pattern} name={field.key} onChange={handleChange} placeholder={field.label} value={field.value} />
                            </span>
                        )}
                    </div>
                </div>
            ))}
            <div className="d-flex flex-column align-items-center mb-4">
                <input type="submit" className="btn btn-primary" value="Save" />
            </div>
            <input type="hidden" name="profile_picture_id" value={profile.profile_picture_id} />
            <input type="hidden" name="csrf_token" value={csrf_token} />
        </form>
    );
}

export default EditProfile;

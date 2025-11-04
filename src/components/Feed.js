import React from 'react';
import Stories from './Stories';
import CreatePost from './CreatePost';
import Posts from './Posts/Posts';

function Feed(props) {
    const current_user = props.current_user;

    return (
        <div className="col-12 col-md-7">

            {/* Create Post */}
            <CreatePost current_user={current_user} get_cookie={props.get_cookie}/>

            {/* Posts */}
            <Posts current_user={current_user} get_cookie={props.get_cookie} />
        </div>
    );
}

export default Feed;

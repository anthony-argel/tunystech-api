const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PostSchema = new Schema({
    post: {type: String, required: true},
    title: {type:String, required: true},
    postdate: {type: Date, required: true},
    lastupdate: {type: Date, required: true},
    visible: {type: Boolean, required: true},
    linkedto: {type: String}
});

module.exports = mongoose.model('Post', PostSchema);
const express = require('express');
const router = express.Router();
const {body, validationResult} = require('express-validator');
const Post = require('../models/post');
const {DateTime} = require('luxon');

// blog posts
router.post('/', (req, res, next) => {
    const newPost = new Post({
      title: req.body.title,
      post: req.body.post,
      postdate: DateTime.now(),
      lastupdate: DateTime.now(),
      visible:false,
      linkedto: req.body.linker
    }).save((err, result) => {
      if(err) {return next(err);}
      res.json({message:'posted!'});
    });
});

router.delete('/:id', (req, res, next) => {
  Post.findByIdAndDelete({_id: req.params.id}).exec((err, result) => {
    if(err) {
      return next(err);
    }
    else {
      res.status(200).json({message:'success'});
    }
  })
})

router.put('/:id', (req, res, next) => {
  const updateData = {};
  if(req.body.post !== '' && typeof req.body.post !== 'undefined') {
    updateData.post = req.body.post;
  }
  if(req.body.title !== '' && typeof req.body.title !== 'undefined') {
    updateData.title = req.body.title;
  }
  if(typeof req.body.visible !== 'undefined') {
    updateData.visible = req.body.visible;
  }
  if(typeof req.body.pleaseUpdate !== 'undefined') {
    updateData.lastupdate = DateTime.now();
  }
  if(typeof req.body.linker !== 'undefined') {
    updateData.linkedto = req.body.linker;
  }
  Post.findByIdAndUpdate(req.params.id, updateData, (err, result) => {
    if(err) {return next(err)}
    else {
      res.status(200).json({message:'success'})
    }
  })
})



module.exports = router;
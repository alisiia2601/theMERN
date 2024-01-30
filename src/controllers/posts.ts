import { Request, Response } from "express";
import mongoose from "mongoose";
import Post from "../models/Post";
import { assertDefined } from "../util/asserts";

export const create = async (req: Request, res: Response) => {
  assertDefined(req.userId);
  const { title, link, body } = req.body;

  try {
    const post = new Post({
      title,
      link,
      body,
      author: req.userId,
    });

    if (req.file) {
      const dbConnection = mongoose.connection;

      const bucket = new mongoose.mongo.GridFSBucket(dbConnection.db, {
        bucketName: "images",
      });

      const uploadStream = bucket.openUploadStream(req.file.originalname);
      const fileId = uploadStream.id;

      await new Promise((resolve, reject) => {
        uploadStream.once("finish", resolve);
        uploadStream.once("error", reject);

        uploadStream.end(req.file?.buffer);
      });

      post.image = {
        mimeType: req.file.mimetype,
        size: req.file.size,
        id: fileId,
      };
    }

    const savedPost = await post.save();
    console.log({savedPost})
    res.status(201).json(savedPost);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Failed to create post" });
  }
};

export const getAllPosts = async (req: Request, res: Response) => {
  const limit = parseInt(req.query.limit?.toString() || "5");
  const page = parseInt(req.query.page?.toString() || "1");

  if (isNaN(page) || isNaN(limit)) {
    res.status(400).json({
      message: "Malformed query object number" + req.query.toString(),
    });
  }

  const posts = await Post.find({}, "-comments")
    .sort({ createdAt: "descending" })
    .limit(limit)
    .skip(limit * (page - 1))
    .populate("author", "userName");

  const totalCount = await Post.countDocuments();

  res.status(200).json({
    posts,
    totalPages: Math.ceil(totalCount / limit),
    query: req.query,
  });
};

export const getPost = async (req: Request, res: Response) => {
  const { id } = req.params;

  const post = await Post.findById(id)
    .populate("author")
    .populate("comments.author");

  if (!post) {
    return res.status(404).json({ message: "No posts found for id: " + id });
  }

  post.upvote;
  post.downvote;

  res.status(200).json(post);
};

export const updatePost = async (req: Request, res: Response) => {
  assertDefined(req.userId);

  const { title, link, body } = req.body;

  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res
        .status(404)
        .json({ message: "No post found" });
    }

    if (post.author.toString() !== req.userId) {
      return res.status(403).json({ message: "Not authorized" });
    }

    post.title = title || post.title;
    post.link = link || post.link;
    post.body = body || post.body;

    const updatedPost = await post.save();
    console.log(req.body)

    res.status(200).json(updatedPost);
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error with updating post" });
  }
};

export const deletePost = async (req: Request, res: Response) => {
  const { postId } = req.params;
  const { userId } = req;
  assertDefined(userId);

  const post = await Post.findById(postId);

  if (!post) {
    return res
      .status(404)
      .json({ message: "Post wasn`t found for id: " + postId });
  }

  if (post.author.toString() !== userId) {
    return res.status(403).json({ message: "Not authorized" });
  }

  await post.deleteOne();

  return res.status(200).json({ message: "Post deleted" });
};


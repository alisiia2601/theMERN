import {Document} from "mongoose"

interface IPost extends Document {
    title: string;
    link?: string,
    userId: string;

}
import mongoose, { Schema } from 'mongoose'

const communitySchema = new Schema({
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    }
})

export const Community = mongoose.model('Community', communitySchema)
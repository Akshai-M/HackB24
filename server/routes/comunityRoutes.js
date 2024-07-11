import express from 'express'
import { createCommunity, deleteCommunity, getCommunities } from '../controllers/communityController.js'
import { authorizeRoles, verifyJWT } from '../middlewares/auth.middleware.js'

const router = express.Router()

router.post('/createCommunity', verifyJWT, authorizeRoles('ADMIN'), createCommunity)
router.get('/getCommunities', getCommunities)
router.delete('/deleteCommunity/:id', verifyJWT, authorizeRoles('ADMIN'), deleteCommunity)

export default router
// SAFE: Uses an authorization check (userId from session) in the WHERE clause to prevent IDOR.
import { Request, Response } from 'express';
import { BasketModel } from '../models/basket';

export async function retrieveBasket(req: Request, res: Response) {
    const id = req.params.id;
    const userId = req.user.id; // Trusted identifier from the session
    const basket = await BasketModel.findOne({ where: { id, userId } });
    if (basket) {
        res.json(basket);
    } else {
        res.status(404).send('Not found');
    }
}

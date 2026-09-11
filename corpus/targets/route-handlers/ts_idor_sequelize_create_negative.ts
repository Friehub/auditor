// SAFE: Uses the trusted BasketId from the user's session instead of trusting the request body.
import { Request, Response } from 'express';
import { BasketItemModel } from '../models/basketItem';

export async function addBasketItem(req: Request, res: Response) {
    const BasketId = req.session.basketId; // Trusted identifier
    const ProductId = req.body.ProductId;
    const quantity = req.body.quantity;
    
    const basketItem = await BasketItemModel.create({ BasketId, ProductId, quantity });
    res.json(basketItem);
}

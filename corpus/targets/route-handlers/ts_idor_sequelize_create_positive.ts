// observation: User input (BasketId) is used directly to create an object via Sequelize without validating ownership.
// improvement: Ensure the user owns the parent object by extracting the BasketId from the trusted session rather than the request body.
import { Request, Response } from 'express';
import { BasketItemModel } from '../models/basketItem';

export async function addBasketItem(req: Request, res: Response) {
    const BasketId = req.body.BasketId;
    const ProductId = req.body.ProductId;
    const quantity = req.body.quantity;
    
    const basketItem = await BasketItemModel.create({ BasketId, ProductId, quantity });
    res.json(basketItem);
}

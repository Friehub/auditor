// observation: User input is used directly to query an object via Sequelize without validating ownership, leading to an Insecure Direct Object Reference (IDOR).
// improvement: Ensure the user owns the object by filtering on a trusted userId from the session, or perform an authorization check before returning the object.
import { Request, Response } from 'express';
import { BasketModel } from '../models/basket';

export async function retrieveBasket(req: Request, res: Response) {
    const id = req.params.id;
    const basket = await BasketModel.findOne({ where: { id } });
    if (basket) {
        res.json(basket);
    } else {
        res.status(404).send('Not found');
    }
}

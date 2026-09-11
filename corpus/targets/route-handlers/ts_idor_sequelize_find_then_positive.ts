// observation: User input is used directly to query an object via Sequelize without validating ownership, leading to IDOR.
import { Request, Response } from 'express';

export function retrieveBasket(req: Request, res: Response) {
    const id = req.params.id;
    BasketModel.findOne({ where: { id } })
        .then((basket: any) => {
            if (basket) {
                res.json(basket);
            }
        });
}
